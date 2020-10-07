package runner

import (
	"regexp"

	"github.com/Netflix/titus-executor/logger"

	"github.com/Netflix/metrics-client-go/metrics"
	"github.com/Netflix/titus-executor/api/netflix/titus"
	"github.com/Netflix/titus-executor/config"
	titusdriver "github.com/Netflix/titus-executor/executor/drivers"
	"github.com/Netflix/titus-executor/executor/runtime/docker"
	runtimeTypes "github.com/Netflix/titus-executor/executor/runtime/types"
	"github.com/Netflix/titus-executor/filesystems"
	"github.com/Netflix/titus-executor/models"
	"github.com/Netflix/titus-executor/uploader"
	"github.com/hashicorp/go-multierror"
	"github.com/sirupsen/logrus"

	"context"
	"fmt"
	"os"
	"sync"
	"time"
)

// Config is runner config

type Task struct {
	TaskID    string
	TitusInfo *titus.ContainerInfo
	Mem       int64
	CPU       int64
	Gpu       int64
	Disk      uint64
	Network   uint64
}

// Runner maintains in memory state for the Task runner
type Runner struct {
	// const:
	metrics       metrics.Reporter
	metricsTagger tagger // the presence of tagger indicates extra Atlas tag is enabled
	runtime       runtimeTypes.Runtime
	config        config.Config

	container *runtimeTypes.Container
	watcher   *filesystems.Watcher

	// Close this channel to start killing the container
	killOnce    sync.Once
	killChan    chan struct{}
	StoppedChan chan struct{}
	UpdatesChan chan Update
}

// StartTask constructs a new Executor object with the default (docker) runtime, and starts the task
func StartTask(ctx context.Context, task Task, m metrics.Reporter, cfg config.Config, dockerCfg docker.Config) (*Runner, error) {
	dockerRuntime, err := docker.NewDockerRuntime(ctx, m, dockerCfg, cfg)
	if err != nil {
		return nil, err
	}
	return StartTaskWithRuntime(ctx, task, m, dockerRuntime, cfg)
}

// StartTaskWithRuntime builds an Executor using the provided Runtime factory func, and starts the task
func StartTaskWithRuntime(ctx context.Context, task Task, m metrics.Reporter, rp runtimeTypes.ContainerRuntimeProvider, cfg config.Config) (*Runner, error) {
	ctx = logger.WithLogger(ctx, logrus.NewEntry(logrus.StandardLogger()).WithField("TaskID", task.TaskID))

	metricsTagger, _ := m.(tagger) // metrics.Reporter may or may not implement tagger interface.  OK to be nil
	labels := map[string]string{
		models.ExecutorPidLabel: fmt.Sprintf("%d", os.Getpid()),
		models.TaskIDLabel:      task.TaskID,
	}

	// Should we remove this?
	if len(task.TitusInfo.GetIamProfile()) > 0 {
		labels["ec2.iam.role"] = task.TitusInfo.GetIamProfile()
	}

	resources := &runtimeTypes.Resources{
		Mem:     task.Mem,
		CPU:     task.CPU,
		GPU:     task.Gpu,
		Disk:    task.Disk,
		Network: task.Network,
	}

	startTime := time.Now()
	runner := &Runner{
		metrics:       m,
		metricsTagger: metricsTagger,
		config:        cfg,
		killChan:      make(chan struct{}),
		UpdatesChan:   make(chan Update, 10),
		StoppedChan:   make(chan struct{}),
		container:     runtimeTypes.NewContainer(task.TaskID, task.TitusInfo, resources, labels, cfg),
	}

	rt, err := rp(ctx, runner.container, startTime)
	if err != nil {
		return nil, err
	}
	runner.runtime = rt

	go runner.startRunner(ctx, startTime)
	go func() {
		<-ctx.Done()
		// Kill the running container if there is one, shut it down
		runner.Kill()
	}()

	return runner, nil
}

// Kill is idempotent, and will either kill a Task, or prevent a new one from being spawned
func (r *Runner) Kill() {
	r.killOnce.Do(func() {
		close(r.killChan)
	})
}

func (r *Runner) startRunner(ctx context.Context, startTime time.Time) {
	defer close(r.UpdatesChan)
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	defer close(r.StoppedChan)

	updateChan := make(chan update, 10)
	go r.runContainer(ctx, startTime, updateChan)

	var lastUpdate *update
	for update := range updateChan {
		logger.G(ctx).WithField("update", update).Debug("Processing update")
		// This is okay, because it only gets references _after_ loop termination.
		lastUpdate = &update // nolint:scopelint
		if update.status.IsTerminalStatus() {
			break
		}
		r.updateStatusWithDetails(ctx, update.status, update.msg, update.details)
	}

	if lastUpdate == nil {
		r.updateStatusWithDetails(ctx, titusdriver.Lost, "Task run stopped without making any progress", nil)
		return
	}

	r.doShutdown(ctx, *lastUpdate)
	badUpdate, ok := <-updateChan
	if ok {
		panic(fmt.Sprintf("Received update after Task was in terminal status: %+v", badUpdate))
	}
}

type update struct {
	status  titusdriver.TitusTaskState
	msg     string
	details *runtimeTypes.Details
}

func (r *Runner) prepareContainer(ctx context.Context) update {
	logger.G(ctx).Debug("Running prepare")
	prepareCtx, prepareCancel := context.WithCancel(ctx)
	defer prepareCancel()
	go func() {
		select {
		case <-r.killChan:
			logger.G(ctx).Debug("Got cancel in prepare")
			prepareCancel()
		case <-prepareCtx.Done():
		}
	}()
	// When Create() returns the host may have been modified to create storage and pull the image.
	// These steps may or may not have completed depending on if/where a failure occurred.
	if err := r.runtime.Prepare(prepareCtx); err != nil {
		r.metrics.Counter("titus.executor.launchTaskFailed", 1, nil)
		logger.G(ctx).Error("Task failed to create container: ", err)
		// Treat registry pull errors as LOST and non-existent images as FAILED.
		switch err.(type) {
		case *runtimeTypes.RegistryImageNotFoundError, *runtimeTypes.InvalidSecurityGroupError, *runtimeTypes.BadEntryPointError, *runtimeTypes.InvalidConfigurationError:
			logger.G(ctx).Error("Returning TASK_FAILED for Task: ", err)
			return update{status: titusdriver.Failed, msg: err.Error()}
		}
		logger.G(ctx).Error("Returning TASK_LOST for Task: ", err)
		return update{status: titusdriver.Lost, msg: err.Error()}
	}

	return update{status: titusdriver.Starting, msg: "starting"}
}

// This is just splitting the "run" part of the of the runner
func (r *Runner) runContainer(ctx context.Context, startTime time.Time, updateChan chan update) {
	defer close(updateChan)
	select {
	case <-r.killChan:
		logger.G(ctx).Error("Task was killed before Task was created")
		return
	case <-ctx.Done():
		logger.G(ctx).Error("Task context was terminated before Task was created")
		return
	default:
	}
	r.maybeSetDefaultTags(ctx) // initialize metrics.Reporter default tags
	updateChan <- update{status: titusdriver.Starting, msg: "creating"}

	prepareUpdate := r.prepareContainer(ctx)
	updateChan <- prepareUpdate
	if prepareUpdate.status.IsTerminalStatus() {
		logger.G(ctx).WithField("prepareUpdate", prepareUpdate).Debug("Prepare was terminal")
		return
	}

	logDir, details, statusChan, err := r.runtime.Start(ctx)
	if err != nil { // nolint: vetshadow
		r.metrics.Counter("titus.executor.launchTaskFailed", 1, nil)
		logger.G(ctx).Info("start container: ", err)

		switch err.(type) {
		case *runtimeTypes.BadEntryPointError:
			logger.G(ctx).Info("Returning TaskState_TASK_FAILED for Task: ", err)
			updateChan <- update{status: titusdriver.Failed, msg: err.Error(), details: details}
		}
		logger.G(ctx).Info("Returning TASK_LOST for Task: ", err)
		updateChan <- update{status: titusdriver.Lost, msg: err.Error(), details: details}
		return
	}

	err = r.maybeSetupExternalLogger(ctx, logDir)
	if err != nil {
		logger.G(ctx).Error("Unable to setup logging for container: ", err)
		updateChan <- update{status: titusdriver.Lost, msg: err.Error(), details: details}
		return
	}

	if details == nil {
		logger.G(ctx).Fatal("Unable to fetch Task details")
	}
	r.metrics.Counter("titus.executor.taskLaunched", 1, nil)

	r.monitorContainer(ctx, startTime, statusChan, updateChan, details)
}

func (r *Runner) maybeSetDefaultTags(ctx context.Context) {
	// If extra Atlas tags is enabled, initialize metrics.Reporter with default tags t.jobId and t.taskId
	jobID := r.container.TitusInfo.TitusProvidedEnv["TITUS_JOB_ID"]
	if r.metricsTagger != nil && len(jobID) > 0 {
		tags := map[string]string{
			"t.jobId":  jobID,
			"t.taskId": r.container.TaskID,
		}
		r.metricsTagger.append(tags)
		logger.G(ctx).Infof("Set Atlas default tags to: %s", tags)
	}
}

func (r *Runner) monitorContainer(ctx context.Context, startTime time.Time, statusChan <-chan runtimeTypes.StatusMessage, updateChan chan update, details *runtimeTypes.Details) { // nolint: gocyclo
	lastMessage := ""
	runningSent := false

	for {
		select {
		case statusMessage, ok := <-statusChan:
			if !ok {
				updateChan <- update{status: titusdriver.Lost, msg: "Lost connection to runtime driver", details: details}
				return
			}
			msg := statusMessage.Msg
			logger.G(ctx).WithField("statusMessage", statusMessage).Info("Processing msg")

			switch statusMessage.Status {
			case runtimeTypes.StatusRunning:
				r.handleTaskRunningMessage(ctx, msg, &lastMessage, &runningSent, startTime, details, updateChan)
				// Error code 0
			case runtimeTypes.StatusFinished:
				if msg == "" {
					msg = "finished"
				}
				updateChan <- update{status: titusdriver.Finished, msg: msg, details: details}
				return
			case runtimeTypes.StatusFailed:
				updateChan <- update{status: titusdriver.Failed, msg: msg, details: details}
				return
			default:
				updateChan <- update{status: titusdriver.Lost, msg: msg, details: details}
				return
			}
		case <-r.killChan:
			logger.G(ctx).Info("Received kill signal")
			return
		case <-ctx.Done():
			return
		}
	}
}

func (r *Runner) handleTaskRunningMessage(ctx context.Context, msg string, lastMessage *string, runningSent *bool, startTime time.Time, details *runtimeTypes.Details, updateChan chan update) {
	// no need to Update the status if Task is running and the message is the same as the last one
	// The first time this is called *runningSent should be false, so it'll always trigger
	if msg == *lastMessage && *runningSent {
		return
	}

	// The msg for the first runningSent will always be "running"
	if !(*runningSent) {
		if msg == "" {
			msg = "running"
		}
		r.metrics.Timer("titus.executor.containerStartTime", time.Since(startTime), r.container.ImageTagForMetrics())
	}

	updateChan <- update{status: titusdriver.Running, msg: msg, details: details}
	*runningSent = true
	*lastMessage = msg

}

func (r *Runner) doShutdown(ctx context.Context, lastUpdate update) { // nolint: gocyclo
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	logger.G(ctx).WithField("lastUpdate", lastUpdate).WithField("wasKilled", r.wasKilled()).Debug("Handling shutdown")
	var errs *multierror.Error

	killStartTime := time.Now()
	// Are we in a situation where the container exited gracefully, or less than gracefully?
	// We need to stop the container
	if err := r.runtime.Kill(ctx); err != nil {
		// TODO(Andrew L): There may be leaked resources that are not being
		// accounted for. Consider forceful cleanup or tracking leaked resources.
		logger.G(ctx).Error("Failed to fully complete primary kill actions: ", err)
		switch lastUpdate.status {
		case titusdriver.Finished:
		case titusdriver.Failed:
		default:
			errs = multierror.Append(errs, err)
		}
	}

	if r.watcher != nil {
		if err := r.watcher.Stop(); err != nil {
			logger.G(ctx).Error("Error while shutting down watcher for: ", err)
			errs = multierror.Append(errs, err)
		}
	}

	if err := r.runtime.Cleanup(ctx); err != nil {
		logger.G(ctx).Error("Cleanup failed: ", err)
		errs = multierror.Append(errs, err)
	}
	r.metrics.Counter("titus.executor.taskCleanupDone", 1, nil)
	msg := lastUpdate.msg

	if err := errs.ErrorOrNil(); err != nil {
		msg = fmt.Sprintf("%+v", err)
	}

	if lastUpdate.status == titusdriver.Finished {
		// TODO(Andrew L): There may be leaked resources that are not being
		// accounted for. Consider forceful cleanup or tracking leaked resources.
		// If the Task finished successfully, include any info about cleanup errors
		r.updateStatusWithDetails(ctx, lastUpdate.status, msg, lastUpdate.details)
	} else if r.wasKilled() {
		// Funnily enough, we can end up in KILLED and FINISHED -- if the Task exits, and then gets a KILL from the Titus / Mesos master
		// while shutting down, it'll get stuck in weird world. Here, we will send a TASK_FINISHED result, over a TASK_KILLED.
		// TODO(Sargun): Consider. Is this the right decision?
		r.updateStatusWithDetails(ctx, titusdriver.Killed, msg, lastUpdate.details)
	} else if !lastUpdate.status.IsTerminalStatus() {
		r.updateStatusWithDetails(ctx, titusdriver.Lost, "Container lost -- Unknown", lastUpdate.details)
		logger.G(ctx).Error("Container killed while non-terminal!")
	} else {
		r.updateStatusWithDetails(ctx, lastUpdate.status, lastUpdate.msg, lastUpdate.details)
	}

	r.metrics.Timer("titus.executor.containerCleanupTime", time.Since(killStartTime), r.container.ImageTagForMetrics())
}

func (r *Runner) wasKilled() bool {
	select {
	case <-r.killChan:
		return true
	default:
		return false
	}
}

func (r *Runner) maybeSetupExternalLogger(ctx context.Context, logDir string) error {
	if logDir == "" {
		logger.G(ctx).Info("Not starting external logger")
		return nil
	}
	logger.G(ctx).Info("Starting external logger")

	uploadCheckInterval, err := r.container.GetLogUploadCheckInterval()
	if err != nil {
		return err
	}
	uploadThresholdTime, err := r.container.GetLogUploadThresholdTime()
	if err != nil {
		return err
	}
	stdioCheckInterval, err := r.container.GetLogStdioCheckInterval()
	if err != nil {
		return err
	}
	keepAfterUpload, err := r.container.GetKeepLocalFileAfterUpload()
	if err != nil {
		return err
	}

	uploadDir := r.container.UploadDir("logs")

	var uploadRegexp *regexp.Regexp

	uploadRegexpStr := r.container.TitusInfo.GetLogUploadRegexp()
	if uploadRegexpStr != "" {
		var err error
		uploadRegexp, err = regexp.Compile(uploadRegexpStr)
		if err != nil {
			return err
		}
	}

	wConf := filesystems.NewWatchConfig(logDir, uploadDir, uploadRegexp, uploadCheckInterval, uploadThresholdTime, stdioCheckInterval, keepAfterUpload)

	uploader, err := uploader.NewUploader(&r.config, r.container.TitusInfo, r.container.TaskID, r.metrics)
	if err != nil {
		return err
	}

	r.watcher, err = filesystems.NewWatcher(r.metrics, wConf, uploader)
	if err != nil {
		return err
	}

	return r.watcher.Watch(ctx)
}

func (r *Runner) updateStatusWithDetails(ctx context.Context, status titusdriver.TitusTaskState, msg string, details *runtimeTypes.Details) {
	l := logger.G(ctx).WithField("msg", msg).WithField("taskStatus", status)
	select {
	case r.UpdatesChan <- Update{
		TaskID:  r.container.TaskID,
		State:   status,
		Mesg:    msg,
		Details: details,
	}:
		l.Info("Updating Task status")
	case <-ctx.Done():
		l.Warn("Not sending update, because UpdatesChan Blocked, (or closed), and context completed")
	}
}

// Update encapsulates information on the updatechan about Task status updates
type Update struct {
	TaskID  string
	State   titusdriver.TitusTaskState
	Mesg    string
	Details *runtimeTypes.Details
}
