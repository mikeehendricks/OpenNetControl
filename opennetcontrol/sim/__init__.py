from .base import SimDevice
from .ios_like import IosXeSim, NxosSim, IcxSim, CxSim
from .firewalls import FortiSim, PanSim
from .mikrotik_sim import RouterOsSim
from .wireless import UnleashedSim, InstantSim

SIM_CLASSES = {c.platform: c for c in (IosXeSim, NxosSim, IcxSim, CxSim, FortiSim, PanSim, RouterOsSim, UnleashedSim, InstantSim)}
