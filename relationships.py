from stix2 import MemoryStore, Filter
from itertools import chain


def get_related(thesrc, src_type, rel_type, target_type, reverse=False):
    relationships = thesrc.query([
        Filter('type', '=', 'relationship'),
        Filter('relationship_type', '=', rel_type),
        Filter('revoked', '=', False),
        Filter('x_mitre_deprecated', "=", False)
    ])

    # stix_id => [ { relationship, related_object_id } for each related object ]
    id_to_related = {}

    # build the dict
    for relationship in relationships:
        if (src_type in relationship.source_ref and target_type in relationship.target_ref):
            if (relationship.source_ref in id_to_related and not reverse) or (
                    relationship.target_ref in id_to_related and reverse):
                # append to existing entry
                if not reverse:
                    id_to_related[relationship.source_ref].append({
                        "relationship": relationship,
                        "id": relationship.target_ref
                    })
                else:
                    id_to_related[relationship.target_ref].append({
                        "relationship": relationship,
                        "id": relationship.source_ref
                    })
            else:
                # create a new entry
                if not reverse:
                    id_to_related[relationship.source_ref] = [{
                        "relationship": relationship,
                        "id": relationship.target_ref
                    }]
                else:
                    id_to_related[relationship.target_ref] = [{
                        "relationship": relationship,
                        "id": relationship.source_ref
                    }]
    # all objects of relevant type
    if not reverse:
        targets = thesrc.query([
            Filter('type', '=', target_type),
            Filter('revoked', '=', False)
        ])
    else:
        targets = thesrc.query([
            Filter('type', '=', src_type),
            Filter('revoked', '=', False)
        ])

    # build lookup of stixID to stix object
    id_to_target = {}
    for target in targets:
        id_to_target[target.id] = target

    # build final output mappings
    output = {}
    for stix_id in id_to_related:
        value = []
        for related in id_to_related[stix_id]:
            if not related["id"] in id_to_target:
                continue  # targeting a revoked object
            value.append({
                "object": id_to_target[related["id"]],
                "relationship": related["relationship"]
            })
        output[stix_id] = value
    return output


# software:group
def software_used_by_groups(thesrc):
    """returns group_id => {software, relationship} for each software used by the group."""
    return get_related(thesrc, "intrusion-set", "uses", "tool") + get_related(thesrc, "intrusion-set", "uses",
                                                                              "malware")


def groups_using_software(thesrc):
    """returns software_id => {group, relationship} for each group using the software."""
    return get_related(thesrc, "intrusion-set", "uses", "tool", reverse=True) + get_related(thesrc, "intrusion-set",
                                                                                            "uses", "malware",
                                                                                            reverse=True)


# technique:group
def techniques_used_by_groups(thesrc):
    """returns group_id => {technique, relationship} for each technique used by the group."""
    return get_related(thesrc, "intrusion-set", "uses", "attack-pattern")


def groups_using_technique(thesrc):
    """returns technique_id => {group, relationship} for each group using the technique."""
    return get_related(thesrc, "intrusion-set", "uses", "attack-pattern", reverse=True)


# technique:software
def techniques_used_by_software(thesrc):
    """return software_id => {technique, relationship} for each technique used by the software."""
    return get_related(thesrc, "malware", "uses", "attack-pattern") + get_related(thesrc, "tool", "uses",
                                                                                  "attack-pattern")


def software_using_technique(thesrc):
    """return technique_id  => {software, relationship} for each software using the technique."""
    return get_related(thesrc, "malware", "uses", "attack-pattern", reverse=True) + get_related(thesrc, "tool", "uses",
                                                                                                "attack-pattern",
                                                                                                reverse=True)
# technique:mitigation
def mitigation_mitigates_techniques(thesrc):
    """return mitigation_id => {technique, relationship} for each technique mitigated by the mitigation."""
    return get_related(thesrc, "course-of-action", "mitigates", "attack-pattern", reverse=False)


def technique_mitigated_by_mitigations(thesrc):
    """return technique_id => {mitigation, relationship} for each mitigation of the technique."""
    return get_related(thesrc, "course-of-action", "mitigates", "attack-pattern", reverse=True)


# technique:subtechnique
def subtechniques_of(thesrc):
    """return technique_id => {subtechnique, relationship} for each subtechnique of the technique."""
    return get_related(thesrc, "attack-pattern", "subtechnique-of", "attack-pattern", reverse=True)


def parent_technique_of(thesrc):
    """return subtechnique_id => {technique, relationship} describing the parent technique of the subtechnique"""
    return get_related(thesrc, "attack-pattern", "subtechnique-of", "attack-pattern")[0]
