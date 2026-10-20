"""Lossless bounded evidence partitioning; never automatically schedules paid calls."""

from .ai_costs import compact_evidence, integer
from .evidence import interpretation_evidence
from .models import ValidationError

MAX_PACKETS = 100


def review_packets(report, maximum, *, group_size=3):
    integer(group_size, 1, 20, "review group size")
    source = interpretation_evidence(report)
    base = {**source, "findings": []}
    # Every packet carries every limitation. Never discard gaps to fit a model context.
    compact_evidence(base, maximum)
    groups, current = [], []
    for row in source["findings"]:
        candidate = [*current, row]
        too_large = len(candidate) > group_size
        if not too_large:
            try:
                compact_evidence({**base, "findings": candidate}, maximum)
            except ValidationError:
                too_large = True
        if too_large:
            if current:
                groups.append({**base, "findings": current})
            # A single oversized observation fails; it is never truncated or omitted.
            compact_evidence({**base, "findings": [row]}, maximum)
            current = [row]
        else:
            current = candidate
        if len(groups) >= MAX_PACKETS:
            raise ValidationError("More than 100 review packets; narrow the assessment scope")
    if current or not groups:
        groups.append({**base, "findings": current})
    return groups


def select_packet(report, maximum, *, packet_index=None, group_size=3):
    groups = review_packets(report, maximum, group_size=group_size)
    if packet_index is None:
        if len(groups) != 1:
            raise ValidationError(
                f"Evidence needs {len(groups)} packets. Preview with ai-prepare --structured "
                "--split, then select --packet-index (1-based). No request was sent."
            )
        packet_index = 1
    integer(packet_index, 1, len(groups), "packet index")
    return groups[packet_index - 1], packet_index, len(groups)
