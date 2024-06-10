import os
import json
import argparse
import requests
from copy import deepcopy
from relationships import techniques_used_by_groups
from stix2 import MemoryStore, Filter

path = os.path.dirname(os.path.realpath(__file__))

tech = {
    "techniqueID": "",
    "tactic": "",
    "score": 1,
    "color": "",
    "comment": "",
    "enabled": True,
    "metadata": [],
    "showSubtechniques": False
}


def get_data_from_branch(domain):
    """get the ATT&CK STIX data from MITRE/CTI. Domain should be 'enterprise-attack', 'mobile-attack' or 'ics-attack'. Branch should typically be master."""
    stix_json = requests.get(f"https://raw.githubusercontent.com/mitre-attack/attack-stix-data/master/{domain}/{domain}.json").json()
    return MemoryStore(stix_data=stix_json["objects"])

def filter_scores(techniques,threshold):
    filtered_techniques = []
    for technique in techniques:
        if '.' not in technique['techniqueID']:
            if technique["score"] >= threshold:
                filtered_techniques.append(technique)
        else:
            filtered_techniques.append(technique)
    return filtered_techniques

def main():

    parser = argparse.ArgumentParser(description='Generates ATT&CK Navigator heatmap, merging multiple threat actors techniques.')
    parser.add_argument('-s', '--search', metavar='string', nargs='+', required=True, help='string to be searched in group\'s descrition for a match.')
    parser.add_argument('-o', '--outfile', metavar='string', required=True, help='output json file containing the generated heatmap.')
    parser.add_argument('-t', '--title', metavar='string', required=True, help='tab title for the current analysis.')
    parser.add_argument('--merge-tech', default=True, action=argparse.BooleanOptionalAction, help='increase counter for main technique as well in case just a subtecnique is used (eg: if T1059.001 is used both T1059 and T1059.001 are added to the heatmap)')
    parser.add_argument('--threshold', type=lambda x: int(x) if int(x) > 0 else argparse.ArgumentTypeError(f"{x} is not a positive integer"), required=False, help='a positive integer representing the threshold value')

    args = parser.parse_args()

    verticals = args.search
    outfile = args.outfile
    name = args.title
    merge_tech = args.merge_tech if args.merge_tech else False
    threshold = args.threshold if args.threshold else 0

    print('[+] Downloading latest version of MITRE ATT&CK')
    src = get_data_from_branch("enterprise-attack")

    print('[+] The following verticals have been selected:')
    groups = []
      
    for vertical in verticals:
        print(f'[-] {vertical.capitalize()}')
        if vertical != '*':
            groups += src.query([Filter("type", "=", "intrusion-set"),
                                Filter("description", "contains", vertical),
                                Filter('revoked', '=', False),
                                Filter('x_mitre_deprecated', "=", False)])
        else:
            groups += src.query([Filter("type", "=", "intrusion-set"),
                                 Filter('revoked', '=', False),
                                 Filter('x_mitre_deprecated', "=", False)]) 


    print(f"[+] The following groups have been identified targeting: {', '.join(verticals)}")
    deduped_groups = []
    # [deduped_groups.append(x) for x in groups if x not in deduped_groups]
    
    for x in groups:
        if x not in deduped_groups: # and not x['revoked'] and not x.get('x_mitre_deprecated',False):
            deduped_groups.append(x)
            print(f"[-] {x['name']}")

    groups_using_tech = techniques_used_by_groups(src)

    print('[+] Loading ATT&CK navigator template')
    with open('{0}/template.json'.format(path),'r') as f:
        allt = json.load(f)
    max_score = 1
    appended_t = []
    print(f"[+] Merging techniques from {len(deduped_groups)} different groups.")
    for group in deduped_groups:
        if group['id'] in groups_using_tech:
            for technique in groups_using_tech[group['id']]:
                external_id = [x['external_id'] for x in technique['object']['external_references'] if
                               x['source_name'] == 'mitre-attack'][0]
                for tactic in technique['object']['kill_chain_phases']:
                    t_name = tactic['phase_name']
                    to_p = []
                    if '.' in external_id and merge_tech:
                        main_id = external_id.split('.')[0]
                        to_p.append(main_id)
                    to_p.append(external_id)
                    for proc in to_p:
                        if (t_name,proc) in appended_t:
                            target = [x for x in allt['techniques'] if x['techniqueID'] == proc and x['tactic'] == t_name]
                            target[0]['score'] += 1
                            if target[0]['score'] > max_score:
                                max_score += 1

                        else:
                            new_t = deepcopy(tech)
                            new_t['techniqueID'] = proc
                            new_t['tactic'] = t_name
                            allt['techniques'].append(new_t)
                            appended_t.append((t_name,proc))
        else:
            # print(f'# NO Techniques for gorup: {group['name']}')
            pass
    
    if threshold  != 0:
        print(f'[+] Filtering out Techniques with score < {threshold}')
        allt['techniques'] = filter_scores(allt['techniques'], threshold)
    
    allt['name'] = name
    allt['gradient']['minValue'] = 1
    allt['gradient']['maxValue'] = max_score
    
    try:
        with open(f'{path}/{outfile}.json','w') as f:
            f.write(json.dumps(allt,indent=4))
        print('[+] Processing done!')
    except Exception as e:
        print(f'[!] ERROR writing to file: {e}')


if __name__ == '__main__':
    main()