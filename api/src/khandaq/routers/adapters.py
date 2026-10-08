"""``GET /api/adapters`` (spec 027): the adapters a run can use, for the console's run launcher.

Any signed-in user may read it: it describes the installed tools, not engagement data.
"""

from __future__ import annotations

from fastapi import APIRouter, Depends

from ..adapters import all_manifests
from ..deps import current_user
from ..models import User
from ..schemas import AdapterOut

router = APIRouter(prefix="/api", tags=["adapters"])


@router.get("/adapters", response_model=list[AdapterOut])
def list_adapters(_user: User = Depends(current_user)) -> list[AdapterOut]:
    return [
        AdapterOut(
            name=m.name,
            version=m.version,
            phases=m.phases,
            frameworks=m.frameworks,
            builtin=m.builtin,
            paces_requests=m.paces_requests,
        )
        for m in all_manifests()
    ]
