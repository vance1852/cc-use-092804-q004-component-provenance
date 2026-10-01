"""部件来源与兼容放行链服务向 API 和命令行暴露的稳定错误。"""


class ProvenanceError(RuntimeError):
    code = "provenance_error"
    status = 400


class NotFound(ProvenanceError):
    code = "not_found"
    status = 404


class Conflict(ProvenanceError):
    code = "conflict"
    status = 409


class Forbidden(ProvenanceError):
    code = "forbidden"
    status = 403


class InvalidState(ProvenanceError):
    code = "invalid_state"
    status = 409


class ValidationFailed(ProvenanceError):
    code = "validation_failed"
    status = 422
