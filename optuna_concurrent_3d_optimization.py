'''
######################################################################################################
Optuna Multi-Objective Optimization using Bayesian Belief Networks (BBN) based on AutomationML Models
Author: Huang Shaofei       Last update: 2026-02-11
######################################################################################################
'''
import numpy as np
import xml.etree.ElementTree as ET
import networkx as nx
import itertools
import math
import os
import re
import argparse
import optuna
import csv
from datetime import datetime
from collections import defaultdict
from pgmpy.models import DiscreteBayesianNetwork
from pgmpy.factors.discrete import TabularCPD
from pgmpy.inference import VariableElimination
from concurrent.futures import ProcessPoolExecutor

############################
# Section 1: Program Start #
############################
instanceHierarchyTag=".//{http://www.dke.de/CAEX}InstanceHierarchy"
internalElementTag=".//{http://www.dke.de/CAEX}InternalElement"
externalInterfaceTag=".//{http://www.dke.de/CAEX}ExternalInterface"
AttributeTag=".//{http://www.dke.de/CAEX}Attribute"
ValueTag=".//{http://www.dke.de/CAEX}Value"
internalLinkTag=".//{http://www.dke.de/CAEX}InternalLink"

pattern = re.compile(r"^V\d{2}$")  # matches V01, V02, ..., V99
start_node = "User"

parser = argparse.ArgumentParser()
parser.add_argument(
    "-i", "--input",
    type=str,
    help="Specify the AML input file"
)
parser.add_argument(
    "-v", "--verbose",
    action="store_true",
    help="Enable verbose output"
)
parser.add_argument(
    "-n", "--num-trials",
    type=int,
    default=10,
    help="Specify number of trials (default is 10)"
)
parser.add_argument(
    "-r", "--num-runs",
    type=int,
    default=1,
    help="Specify number of runs (default is 1)"
)
parser.add_argument(
    "-g", "--graph",
    action="store_true",
    help="Display graph"
)
parser.add_argument(
    "-o", "--output",
    type=str,
    default="output.csv",
    help="Specify the output file name (default is output.csv)"
)
args = parser.parse_args()
amlFile = ET.parse(args.input)
root = amlFile.getroot()

def calculate_days_and_hours(start_date):
    time_difference = datetime.now() - datetime.strptime(start_date, "%Y-%m-%d")
    return time_difference.days, time_difference.seconds // 3600

days, hours = calculate_days_and_hours("2024-01-01")
t = days * 4 + (24 - hours)

sap = 1

#############################################
# Section 2: AML Model Attribute Extraction #
#############################################
allinone_attrib = []  
allinone_tags = []
allinone_text = []
name_id_tag_list = []
name_list = []
id_list = []
tag_list = []
RefPartnerBegin_list = []
RefPartnerTerminate_list = []
InternalLinks = []
probability_data = []
HazardinSystem = []
VulnerabilityinSystem = []
AssetinSystem = []
external_interfaces_list = []
connections = []
interface_to_element_map = {}
connections_mapped = []
result_list = []
number_of_dependents = []
max_num_parents = 0
max_num_children = 0

for k in root.findall('.//'):
    allinone_attrib.append(k.attrib)
    allinone_tags.append(k.tag)
    allinone_text.append(k.text)

for i, component_attrib in enumerate(allinone_attrib):
    name = component_attrib.get('Name')
    ID = component_attrib.get('ID')
    RPA = component_attrib.get('RefPartnerSideA')
    RPB = component_attrib.get('RefPartnerSideB')
    if name:
        name_list.append(name)
    if ID:
        id_list.append(ID)
    if name and ID:
        tag = allinone_tags[i]
        tag_list.append(tag)
        name_id_tag_list.append({'Name': name, 'ID': ID, 'Tag': tag})
    if RPA:
        RefPartnerBegin_list.append(RPA)
    if RPB:
        RefPartnerTerminate_list.append(RPB)
    if RPA and RPB:
        InternalLinks.append({RPA, RPB})

internal_elements = root.findall(internalElementTag)

def get_attribute_value(internal_element, attribute_name):
    attribute_tag = internal_element.find(f".//{{http://www.dke.de/CAEX}}Attribute[@Name='{attribute_name}']")
    if attribute_tag is not None:
        value_element = attribute_tag.find(ValueTag)
        if value_element is not None:
            return float(value_element.text)
    return None

def calculate_probability_of_failure(failure_rate_value, t):
    failure_rate = float(failure_rate_value)
    return 1 - math.exp(-(failure_rate * t))

def calculate_probability_of_human_error(human_error_percentage_value, t):
    human_error_in_percent = float(human_error_percentage_value)
    human_error_rate = human_error_in_percent / (100 * 8760)
    return 1 - math.exp(-(human_error_rate * t))

def generate_cpd_values_hazard(num_parents):
    cpd_values = [[0] * (2 ** num_parents) for _ in range(2)]
    for i in range(2 ** num_parents):
        num_ones = bin(i).count('1')
        cpd_values[0][i] = (num_parents - num_ones) / num_parents
        cpd_values[1][i] = 1 - cpd_values[0][i]
    return cpd_values

for internal_element in internal_elements:
    internal_element_id = internal_element.get('ID')
    internal_element_name = internal_element.get('Name')
    ref_base_system_unit_path = internal_element.get('RefBaseSystemUnitPath')

    failure_rate_value = get_attribute_value(internal_element, 'FailureRatePerHour')
    probability_of_failure = None
    if failure_rate_value is not None:
        probability_of_failure = calculate_probability_of_failure(failure_rate_value, t)
    else:
        probability_of_failure = 0

    impact_value = get_attribute_value(internal_element, 'Impact Rating')

    probability_of_exposure_value = get_attribute_value(internal_element, 'Probability of Exposure')
    probability_of_exposure = None
    if probability_of_exposure_value is not None:
        probability_of_exposure = probability_of_exposure_value
    else:
        probability_of_exposure = 0
    
    probability_of_impact_value = get_attribute_value(internal_element, 'Probability of Impact')
    probability_of_impact = None
    if probability_of_impact_value is not None:
        probability_of_impact = probability_of_impact_value
    else:
        probability_of_impact = 0

    probability_of_mitigation_value = get_attribute_value(internal_element, 'Probability of Mitigation')
    probability_of_mitigation = None
    if probability_of_mitigation_value is not None:
        probability_of_mitigation = probability_of_mitigation_value
    else:
        probability_of_mitigation = 0

    human_error_percentage_value = get_attribute_value(internal_element, 'HumanErrorEstimationPercentage')
    probability_of_human_error = None
    if human_error_percentage_value is not None:
        probability_of_human_error = calculate_probability_of_human_error(human_error_percentage_value, t)
    else:
        probability_of_human_error = 0

    internal_element_data = {
        'ID': internal_element_id,
        'Name': internal_element_name,
        'Impact Rating': impact_value,
        'Probability of Failure': probability_of_failure,
        'Probability of Exposure': probability_of_exposure,
        'Probability of Impact' : probability_of_impact,
        'Probability of Mitigation' : probability_of_mitigation,
        'Probability of Human Error': probability_of_human_error,
        'RefBaseSystemUnitPath': ref_base_system_unit_path
    }
    
    if ref_base_system_unit_path.startswith('AssetOfICS/'):
        AssetinSystem.append(internal_element_data)
    elif ref_base_system_unit_path == 'HazardforSystem/Hazard':
        HazardinSystem.append(internal_element_data)
    elif ref_base_system_unit_path == 'VulnerabilityforSystem/Vulnerability':
        VulnerabilityinSystem.append(internal_element_data)
    
    probability_data.append(internal_element_data)

## Data Check

'''
for data in probability_data:
    print("ID:", data['ID'], "Name:", data['Name'], "RefSystemUnitPath:", data['RefBaseSystemUnitPath'], "Impact Rating", data['Impact'],
          "Prob of Failure:", data['Probability of Failure'], "Prob of Exposure:", data['Probability of Exposure'],
          "Prob of Impact:", data['Probability of Impact'], "Prob of Mitigation:", data['Probability of Mitigation'],
          "Prob of Human Error:", data['Probability of Human Error'])
'''

for internal_element in internal_elements:
    external_interfaces = internal_element.findall(externalInterfaceTag)
    if len(external_interfaces) < 5:
        internal_element_id = internal_element.get('ID')
        internal_element_name = internal_element.get('Name')
        for external_interface in external_interfaces:
            external_interface_id = external_interface.get('ID')
            external_interface_name = external_interface.get('Name')
            external_interface_ref_base_class_path = external_interface.get('RefBaseClassPath')
            external_interface_info = {
                'InternalElement ID': internal_element_id,
                'InternalElement Name': internal_element_name,
                'ExternalInterface ID': external_interface_id,
                'ExternalInterface Name': external_interface_name,
                'ExternalInterface RefBaseClassPath': external_interface_ref_base_class_path
                }            
            external_interfaces_list.append(external_interface_info)

for external_interface in external_interfaces_list:
    external_interface_id = external_interface['ExternalInterface ID']
    internal_element_id = external_interface['InternalElement ID']
    interface_to_element_map[external_interface_id] = internal_element_id

for internal_link in root.findall(internalLinkTag):
    ref_partner_a = internal_link.get('RefPartnerSideA')
    ref_partner_b = internal_link.get('RefPartnerSideB')
    if ref_partner_a in interface_to_element_map and ref_partner_b in interface_to_element_map:
        internal_element_a = interface_to_element_map[ref_partner_a]
        internal_element_b = interface_to_element_map[ref_partner_b]
        connection = {'from': internal_element_a, 'to': internal_element_b}
        connections.append(connection)

for connection in connections:
    from_interface = connection['from']
    to_interface = connection['to']
    if from_interface in interface_to_element_map:
        from_element = interface_to_element_map[from_interface]
    else:
        from_element = from_interface
    if to_interface in interface_to_element_map:
        to_element = interface_to_element_map[to_interface]
    else:
        to_element = to_interface
    mapped_connection = {'from': from_element, 'to': to_element}
    connections_mapped.append(mapped_connection)

connections_from_to = defaultdict(list)
connections_to_from = defaultdict(list)
total_elements = set()

for connection in connections_mapped:
    from_element = connection['from']
    to_element = connection['to']
    total_elements.add(from_element)
    total_elements.add(to_element)
    connections_from_to[from_element].append(to_element)
    connections_to_from[to_element].append(from_element)

connections_result_FT = [{'from': k, 'to': v} for k, v in connections_from_to.items()]
connections_result_TF = [{'from': v, 'to': k} for k, v in connections_to_from.items()]
number_of_children =  [{'Element': k, 'Number of children': len(v)} for k, v in connections_from_to.items()]
number_of_parents =  [{'Element': k, 'Number of parents': len(v)} for k, v in connections_to_from.items()]

for element in total_elements:
    child = next((c for c in number_of_children if c['Element'] == element), {'Number of children': 0})
    parent = next((p for p in number_of_parents if p['Element'] == element), {'Number of parents': 0})
    total_dependents = child['Number of children'] + parent['Number of parents']
    result_dict = {
        'Element': element,
        'Number of children': child['Number of children'],
        'Number of parents': parent['Number of parents'],
        'Total Dependents': total_dependents
    }

    for key in result_dict:
        if isinstance(result_dict[key], (int, float)):
            result_dict[key] /= len(total_elements)
    
    result_list.append(result_dict)
    parent = next((p for p in number_of_parents if p['Element'] == element), {'Number of parents': 0})
    num_parents = parent['Number of parents']

    if num_parents > max_num_parents:
        max_num_parents = num_parents
    
    num_children = child['Number of children']

    if num_children > max_num_children:
        max_num_children = num_children

root_nodes = [element for element in total_elements 
              if element not in connections_to_from or len(connections_to_from[element]) == 0]
start_node = next(iter(root_nodes)) if root_nodes else None

print("Start node:", start_node)

############################################################################
# Section 3: Bayesian Belief Network (BBN) Implementation Helper Functions #
############################################################################
def generate_cpd_values_exposure(num_states, num_parents, node, matching_nodes, hazard_node=False, vulnerability_node=False, asset_node=False):
    cpd_values = np.zeros((num_states, 2 ** num_parents))

    if hazard_node:
        if num_parents == 0:
            cpd_values[0, 0] = 0.5
            cpd_values[1, 0] = 0.5
        elif num_parents == 1:
            cpd_values[0, 0] = 1
            cpd_values[0, 1] = 0
            cpd_values[1, 0] = 1 - cpd_values[0, 0]
            cpd_values[1, 1] = 1 - cpd_values[0, 1]
        elif 2 <= num_parents <= max_num_parents:
            cpd_values=generate_cpd_values_hazard(num_parents)

    elif vulnerability_node:
        if pattern.match(matching_nodes[0]['ID']):
            probability_of_mitigation = [
                element for element in VulnerabilityinSystem
                if element['ID'] == matching_nodes[0]['ID']
            ][0]['Probability of Mitigation']  # Retrieve the Probability of Mitigation for the current ID
            
            probability_of_exposure_for_node = matching_nodes[0]['Probability of Exposure'] * (
                1 - probability_of_mitigation
            )
        else:
            probability_of_exposure_for_node = matching_nodes[0]['Probability of Exposure']
        pofe = float(probability_of_exposure_for_node)        
        if num_parents == 0:
            cpd_values[0, 0] = pofe * sap
            cpd_values[1, 0] = 1 - pofe * sap
        elif num_parents >= 1:
            cpd_values[0, :-1] = pofe * sap
            cpd_values[1, :-1] = 1 - pofe * sap
            cpd_values[0, -1] = 0
            cpd_values[1, -1] = 1
    
    elif asset_node:
        ref_base_for_node = matching_nodes[0]['RefBaseSystemUnitPath']    
        if ref_base_for_node.startswith ('AssetOfICS/'):
            probability_of_failure_for_node = matching_nodes[0]['Probability of Failure']

            # Calculate probability of failure based on connected vulnerabilities
            connections_from_to = defaultdict(list)

            for connection in connections_mapped:
                from_element = connection['from']
                if matching_nodes[0]['ID'] == from_element:
                    to_element = connection['to']
                    if re.match(r'^(V|\(V|\[V)\d', to_element):
                        connections_from_to[from_element].append(to_element)

            for asset, vulns in connections_from_to.items():
                num_vulns = len(vulns)

                sum_mitigation = 0.0  # Initialize sum for each asset

                for i in range(num_vulns):
                    matched = [element for element in VulnerabilityinSystem if element['ID'] == vulns[i]]
                    if matched:
                        probability_of_mitigation = matched[0].get('Probability of Mitigation', 0.0)
                        if probability_of_mitigation > 0:
                            sum_mitigation += probability_of_mitigation
                    else:
                        print(f"No matching vulnerability found for ID {vulns[i]}")

                if num_vulns > 0:
                    scaling_factor = 1.0 / num_vulns
                    probability_of_failure_for_node = min(1.0, scaling_factor * sum_mitigation)
                    #print("Asset:", asset, "Probability of failure:", probability_of_failure_for_node)

            if probability_of_failure_for_node:
                poff = float(probability_of_failure_for_node)
                cpd_values[0, :-1] = 1
                cpd_values[1, :-1] = 0
                cpd_values[0, -1] = poff
                cpd_values[1, -1] = 1 - poff
            else:
                cpd_values[0, :-1] = 1
                cpd_values[1, :-1] = 0
                cpd_values[0, -1] = 0
                cpd_values[1, -1] = 1
        elif ref_base_for_node == 'AssetOfICS/User':
            probability_of_human_error_for_node = matching_nodes[0]['Probability of Human Error']
            pofhe = float(probability_of_human_error_for_node)
            cpd_values[0, 0] = pofhe
            cpd_values[1, 0] = 1 - pofhe
        else:
            probability_of_failure_for_node = matching_nodes[0]['Probability of Failure']
            poff = float(probability_of_failure_for_node)
            cpd_values[0, 0] = poff
            cpd_values[1, 0] = 1 - poff


    cpd_values /= np.sum(cpd_values, axis=0)  # Normalize the CPD values
    return cpd_values.reshape((num_states, -1))

def generate_cpd_values_impact_(num_states, num_parents, node, matching_nodes, hazard_node=False, vulnerability_node=False, asset_node=False):
    cpd_values = np.zeros((num_states, 2 ** num_parents))
    current_entry = next((entry for entry in result_list if entry['Element'] == node), None)

    if hazard_node:
        if num_parents == 0:
            cpd_values[0, 0] = 0.5
            cpd_values[1, 0] = 0.5
        elif num_parents == 1:
            cpd_values[0, 0] = 1
            cpd_values[0, 1] = 0
            cpd_values[1, 0] = 1 - cpd_values[0, 0]
            cpd_values[1, 1] = 1 - cpd_values[0, 1]    
        elif 2 <= num_parents <= max_num_parents:
            cpd_values=generate_cpd_values_hazard(num_parents)
    
    elif vulnerability_node:
        if pattern.match(matching_nodes[0]['ID']):
            probability_of_mitigation = [
                element for element in VulnerabilityinSystem
                if element['ID'] == matching_nodes[0]['ID']
            ][0]['Probability of Mitigation']  # Retrieve the Probability of Mitigation for the current ID
            
            probability_of_impact_for_node = matching_nodes[0]['Probability of Impact'] * (
                1 - probability_of_mitigation
            )
        else:
            probability_of_impact_for_node = matching_nodes[0]['Probability of Impact']

        pofi = float(probability_of_impact_for_node)
        if num_parents == 0:
            cpd_values[0, 0] = pofi
            cpd_values[1, 0] = 1 - pofi
        elif num_parents >= 1:
            cpd_values[0, :-1] = 1
            cpd_values[1, :-1] = 0
            cpd_values[0, -1] = pofi
            cpd_values[1, -1] = 1 - pofi
    
    elif asset_node:
        ref_base_for_node = matching_nodes[0]['RefBaseSystemUnitPath']
        if ref_base_for_node.startswith('AssetOfICS/'):
            probability_of_failure_for_node = matching_nodes[0]['Probability of Failure']

            if probability_of_failure_for_node:
                cpd_values[0, :-1] = 1
                cpd_values[1, :-1] = 0
                cpd_values[0, -1] = current_entry['Number of children']
                cpd_values[1, -1] = 1 - current_entry['Number of children']
            else:
                cpd_values[0, :-1] = 1
                cpd_values[1, :-1] = 0
                cpd_values[0, -1] = 0
                cpd_values[1, -1] = 1   
        elif ref_base_for_node == 'AssetOfICS/User':
            cpd_values[0, 0] = current_entry['Number of children']
            cpd_values[1, 0] = 1 - current_entry['Number of children']
        else:
            cpd_values[0, 0] = current_entry['Number of children']
            cpd_values[1, 0] = 1 - current_entry['Number of children']

    cpd_values /= np.sum(cpd_values, axis=0)  # Normalize the CPD values
    return cpd_values.reshape((num_states, -1))

def shortest_path_length(graph, start_node, end_node):
    try:
        # Using networkx's shortest path length function
        length = nx.shortest_path_length(graph, source=start_node, target=end_node)
        return length
    except nx.NetworkXNoPath:
        # If no path exists between the nodes
        return float('inf')

def compute_impact(bbn, source_node, target_node):
    graph = nx.DiGraph(bbn.edges)
    try:
        all_paths = list(nx.all_simple_paths(graph, source=source_node, target=target_node))
        
        if not all_paths:
            print(f"[!] No paths exist between {source_node} and {target_node}.")
            return
        
        sorted_paths = sorted(all_paths, key=len)
        longest_paths = [path for path in sorted_paths if len(path) == len(sorted_paths[-1])]

#        print(f"[*] Longest path(s) from {source_node} to {target_node}:")
#        for i, path in enumerate(longest_paths, 1):
#            print(f"  {i}: {path}")

        impact_scores = []
        
        # Compute impact for each longest path
        for path in longest_paths:
            path_impacts = []
            for i in range(1, len(path) - 1):  # Exclude first and last node
                current_node = path[i]
                prev_node = path[i - 1]  # Previous node in the sequence
                
                # Check if the previous node is a vulnerability
                matching_vuln = next((v for v in VulnerabilityinSystem if v['ID'] == prev_node), None)
                matching_asset = next((a for a in AssetinSystem if a['ID'] == current_node), None)
                
                if matching_vuln and matching_asset:
                    mitigation_prob = matching_vuln.get('Probability of Mitigation', 0)  # Default to 0 if missing
                    impact_rating = matching_asset.get('Impact Rating', 0)  # Default to 0 if missing
                    
                    adjusted_impact = impact_rating * mitigation_prob
                    path_impacts.append(adjusted_impact)
                elif matching_asset:  # Non-vulnerability case, normal impact rating
                    path_impacts.append(matching_asset.get('Impact Rating', 0))

            # Compute average impact for the path
            if path_impacts:
                impact_scores.append(sum(path_impacts) / len(path_impacts))

        # Compute overall average impact across all longest paths
        if impact_scores:
            avg_impact = sum(impact_scores) / len(impact_scores)
#            print(f"[*] Average impact across longest paths: {avg_impact:.4f}")
#        else:
#            print("[!] No impact data found for nodes in the longest paths.")

        return avg_impact
    
    except nx.NetworkXNoPath:
        print(f"[!] No path exists between {source_node} and {target_node}.")
    except nx.NodeNotFound as e:
        print(f"[!] Error: {e}")

#################################################
# Section 4: Optuna Hyperparameter Optimization #
#################################################

def bbn_inference():
    cpds = {}
    cpd_values_list = []
    path_length_betn_nodes= []
    path_length_betn_nodes_final= []
    path_length_final_node = []

    bbn_exposure = DiscreteBayesianNetwork()
    bbn_impact = DiscreteBayesianNetwork()
    connections = connections_mapped
    bbn_exposure.add_nodes_from(total_elements)
    bbn_exposure.add_edges_from([(connection['from'], connection['to']) for connection in connections])
    bbn_impact.add_edges_from([(connection['from'], connection['to']) for connection in connections])

    for node in bbn_exposure.nodes():
        num_parents = len(bbn_exposure.get_parents(node))
        num_states = 2  # Assuming binary states for each node
        matching_hazard_nodes = [element for element in HazardinSystem if element['ID'] == node]
        matching_vulnerability_nodes = [element for element in VulnerabilityinSystem if element['ID'] == node]
        matching_asset_nodes = [element for element in AssetinSystem if element['ID'] == node]

        cpd_values = None

        if matching_hazard_nodes:
            cpd_values = generate_cpd_values_exposure(num_states, num_parents, node, matching_hazard_nodes, hazard_node=True)
        elif matching_vulnerability_nodes:
            cpd_values = generate_cpd_values_exposure(num_states, num_parents, node, matching_vulnerability_nodes, vulnerability_node=True)
        elif matching_asset_nodes:
            cpd_values = generate_cpd_values_exposure(num_states, num_parents, node, matching_asset_nodes, asset_node=True)

        cpd = TabularCPD(variable=node, variable_card=num_states, values=cpd_values,
                        evidence=bbn_exposure.get_parents(node), evidence_card=[2] * num_parents)

        cpds[node] = cpd
        cpd_values_list.append((node, cpd_values.tolist(), cpd.variables, cpd.cardinality))
        
    bbn_exposure.add_cpds(*cpds.values())
    bbn_graph = bbn_exposure.to_markov_model()

    last_node = None
    for element1 in HazardinSystem:
        node1=element1['ID']
        for element2 in result_list:
            node2=element2['Element']
            child_num = element2['Number of children']
            if node1 == node2:
                if child_num == 0:
                    last_node = node1

    for node1, node2 in itertools.product(total_elements, repeat=2):
        if node1 == node2:
            path_length_betn_nodes.append((node1, node2, 0))
        else:
            path_length = shortest_path_length(bbn_graph, node1, node2)
            if path_length == float('inf'):
                path_length_betn_nodes.append((node1, node2, "No path"))
            else:
                path_length_betn_nodes_final.append((node1, node2, path_length, 1/path_length))
                path_length_betn_nodes.append({'Node1': node1, 'Node2': node2, 
                                'Number of hops': path_length, 
                                'Probability': 1/path_length})
                if node2 == last_node:
                    path_length_final_node.append((node1, last_node, path_length, 1/path_length))

    for node in bbn_impact.nodes():
        num_parents = len(bbn_exposure.get_parents(node))
        num_states = 2
        cpd_values = None

        matching_hazard_nodes = [element for element in HazardinSystem if element['ID'] == node]
        matching_vulnerability_nodes = [element for element in VulnerabilityinSystem if element['ID'] == node]
        matching_asset_nodes = [element for element in AssetinSystem if element['ID'] == node]

        if matching_hazard_nodes:
            cpd_values = generate_cpd_values_impact_(num_states, num_parents, node, matching_hazard_nodes, hazard_node=True)
        elif matching_vulnerability_nodes:
            cpd_values = generate_cpd_values_impact_(num_states, num_parents, node, matching_vulnerability_nodes, vulnerability_node=True)
        elif matching_asset_nodes:
            cpd_values = generate_cpd_values_impact_(num_states, num_parents, node, matching_asset_nodes, asset_node=True)

        cpd = TabularCPD(variable=node, variable_card=num_states, values=cpd_values,
                        evidence=bbn_exposure.get_parents(node), evidence_card=[2] * num_parents)

        cpds[node] = cpd
        cpd_values_list.append((node, cpd_values.tolist(), cpd.variables, cpd.cardinality))

    bbn_impact.add_cpds(*cpds.values())

    inference_exposure = VariableElimination(bbn_exposure)
    inference_impact = VariableElimination(bbn_impact)

    for nodes in total_elements:
        if nodes == last_node:
            prob_exposure = inference_exposure.query(variables=[nodes], evidence={start_node:1})
            prob_failure = inference_impact.query(variables=[nodes], evidence={start_node:1})
            cpd_prob = prob_exposure.values
            cpd_failure = prob_failure.values
            impact_score = compute_impact(bbn_exposure, start_node, last_node)
            return cpd_prob[0], impact_score, 1 - cpd_failure[0]
        else:
            pass

def objective(trial):
    mitigation_prob_dict = {}

    n_vulns = len(VulnerabilityinSystem)
    
    mitigation_prob_dict = {str(i): trial.suggest_float(f'Mitigation_V{i:02d}', 0, 1) 
                           for i in range(1, n_vulns + 1)}

    for element in VulnerabilityinSystem:
        if pattern.match(element['ID']):
            index = element['ID'][1:]
            element['Probability of Mitigation'] = mitigation_prob_dict[index]

    return bbn_inference()

def run_study(n_trials, graph, verbose, output):
    study = optuna.create_study(directions=["minimize", "minimize", "maximize"])
    study.optimize(objective, n_trials, timeout=300)

    if graph:
        fig = optuna.visualization.plot_pareto_front(study, target_names=["Likelihood", "Impact", "Availability"])
        fig.update_layout(
            scene=dict(
                aspectmode="manual",
                aspectratio=dict(x=1, y=1, z=1),
                xaxis=dict(range=[0, 0.5]),
                yaxis=dict(range=[0, 0.3]),
                zaxis=dict(range=[0, 0.74]),
                camera=dict(eye=dict(x=1.5, y=1.5, z=1.5))  # Balanced isometric view
            )
        )
        fig.show()

    trial_with_highest_availability = max(study.best_trials, key=lambda t: t.values[2])

    if verbose:
        print(f"Number of trials on the Pareto front: {len(study.best_trials)}")
        print("Trial with highest availability: ")
        print(f"\tTrial: {trial_with_highest_availability.number}")
        print(f"\tParams: {trial_with_highest_availability.params}")
        print(f"\tLikelihood: {trial_with_highest_availability.values[0]}, Impact: {trial_with_highest_availability.values[1]}, Availability: {trial_with_highest_availability.values[2]}")

    params = trial_with_highest_availability.params
    values = trial_with_highest_availability.values
    sorted_params = sorted(enumerate(params.values()), key=lambda item: item[1], reverse=True)
    sorted_indices = [item[0] for item in sorted_params]
    row = sorted_indices + [f"{values[0]:.3f}", f"{values[1]:.3f}", f"{values[2]:.3f}"]

    with open(output, "a", newline="") as file:
        writer = csv.writer(file)
        writer.writerow(row)

if __name__ == "__main__":
    n_trials = args.num_trials
    n_runs = args.num_runs

    if os.path.exists(args.output):
        os.remove(args.output)

    start_time = datetime.now()

    with ProcessPoolExecutor() as executor:
        futures = [
            executor.submit(run_study, n_trials, args.graph, args.verbose, args.output)
            for run in range(n_runs)
        ]
        for future in futures:
            future.result()  # Wait for all processes to complete

    end_time = datetime.now()
    total_time = end_time - start_time  # Compute duration
    hours, remainder = divmod(total_time.seconds, 3600)
    minutes, seconds = divmod(remainder, 60)

    print(f"Total execution time: {hours} hours {minutes} minutes {seconds} seconds")
