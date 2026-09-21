"""Import every ORM model so `Base.metadata` is complete (Alembic, test schema creation).

Composition-root wiring: the one place allowed to know about every module's models. Lives outside
`app.core` so core never depends on business modules.
"""

from app.core.audit import models as _audit_models  # noqa: F401
from app.core.db.base import Base
from app.modules.correlation.infrastructure import models as _correlation_models  # noqa: F401
from app.modules.detection.infrastructure import models as _detection_models  # noqa: F401
from app.modules.identity.infrastructure import models as _identity_models  # noqa: F401
from app.modules.ingestion.infrastructure import models as _ingestion_models  # noqa: F401

metadata = Base.metadata
