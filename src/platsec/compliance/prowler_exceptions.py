class AwsBucketPathCreateException(Exception):
    pass


class AwsProwlerFileException(Exception):
    pass


class AwsBotoAuthException(Exception):
    pass


class PipelineValidationPhaseException(Exception):
    pass


class PipelineNoneError(Exception):
    pass


class ProwlerExecutionError(Exception):
    pass


class EmptySQSMessage(Exception):
    pass
