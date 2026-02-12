'''
#######################################################################################################
BlackEnergy Risk Assessment using Bayesian Belief Networks (BBN) based on AutomationML Models
Author: Huang Shaofei
Last update: 2026-02-11
#######################################################################################################
'''

import numpy as np
import xml.etree.ElementTree as ET
import networkx as nx
import matplotlib.pyplot as plt
import itertools
import math
import re
import argparse
from datetime import datetime
from dataclasses import dataclass
from collections import defaultdict
from pgmpy.models import DiscreteBayesianNetwork
from pgmpy.factors.discrete import TabularCPD
from pgmpy.inference import VariableElimination

@dataclass
class Environment:
    element_tree_root: object
    t: object
    sap: object
    args: object

@dataclass
class AMLData:
    probability_data: object
    HazardinSystem: object
    VulnerabilityinSystem: object
    max_num_parents: int
    total_elements: int
    connections: object
    connections_mapped: object
    result_list: object
    start_node: object
    end_node: object

def create_parser(interactive):
    parser = argparse.ArgumentParser(description="AutomationML-based Bayesian Belief Network Analysis")
    parser.add_argument("-i", "--input", type=str, required=True, help="Specify the AML input file")
    if interactive==False:
        parser.add_argument("-v", "--verbose", action="store_true", help="Enable verbose output")
        parser.add_argument("-n", "--num-trials", type=int, default=10, help="Specify number of trials per run (default is 10)")
        parser.add_argument("-r", "--num-runs", type=int, default=1, help="Specify number of runs (default is 1)")
        parser.add_argument("-g", "--graph", action="store_true", help="Display graph")
        parser.add_argument("-o", "--output", type=str, default="output.csv", help="Specify the output file (default is output.csv)") 
    return parser

def get_valid_date():
    while True:
        date_input = input("Enter system installation date (in the format YYYY-MM-DD) or leave blank for default (2024-01-01): ")
        if not date_input:
            return "2024-01-01"  # Default to 2024-01-01
        try:
            datetime.strptime(date_input, "%Y-%m-%d")
            return date_input
        except ValueError:
            print("Invalid date format. Please try again.")

def calculate_days_and_hours(start_date):
    start_date = datetime.strptime(start_date, "%Y-%m-%d")
    reference_date_input = input("Enter reference date (YYYY-MM-DD) or leave blank for current date: ")
    if reference_date_input.strip():
        reference_date = datetime.strptime(reference_date_input, "%Y-%m-%d")
    else:
        reference_date = datetime.now()
    print("[*]: Reference date:", reference_date)
    time_difference = reference_date - start_date
    days = time_difference.days
    remaining_seconds = time_difference.seconds
    remaining_hours = remaining_seconds // 3600
    return days, remaining_hours

def setup_environment(interactive=True):
    sap = 0
    t = 0
    parser = create_parser(interactive)
    args = parser.parse_args()
    ET_root = ET.parse(args.input).getroot()

    if (interactive):
        start_date_str = get_valid_date()
        print("[*]: System installation date:", start_date_str)
        days, hours = calculate_days_and_hours(start_date_str)
        t = days * 4 + (24 - hours)
        print("Time since installation:", days, "days and ", hours, "hours (Total:", t, "hours)\n")

        while True:
            sap_input = input("Enter attack feasibility factor or leave blank for default (1%): ")
            try:
                if not sap_input:
                    sap_percent = 1  # Default to 1%
                else:
                    sap_percent = float(sap_input)
                if 0.01 <= sap_percent <= 100:
                    sap = sap_percent / 100
                    break
                else:
                    print("[!] ERROR: Input a valid SA value between 0.01% and 100%.")
            except ValueError:
                print("Invalid input. Please enter a numeric value.")
    else:
        time_difference = datetime.now() - datetime.strptime("2024-01-01", "%Y-%m-%d")
        days = time_difference.days
        hours = divmod(time_difference.seconds, 3600)[0]
        t = days * 4 + (24 - hours)
        sap = 1 / 100

    return ET_root, t, sap, args

def get_attribute_value(internal_element, attribute_name):
    ValueTag=".//{http://www.dke.de/CAEX}Value"
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

def check_probability_data(aml_data: AMLData):
    for data in aml_data.probability_data:
        print("ID:", data['ID'], "Name:", data['Name'], "RefSystemUnitPath:", data['RefBaseSystemUnitPath'],
            "Prob of Failure:", data['Probability of Failure'], "Prob of Exposure:", data['Probability of Exposure'],
            "Prob of Impact:", data['Probability of Impact'], "Prob of Mitigation:", data['Probability of Mitigation'],
            "Prob of Human Error:", data['Probability of Human Error'])
        
def process_AML_file(root, t):
    internalElementTag=".//{http://www.dke.de/CAEX}InternalElement"
    externalInterfaceTag=".//{http://www.dke.de/CAEX}ExternalInterface"
    internalLinkTag=".//{http://www.dke.de/CAEX}InternalLink"

    max_num_parents = 0

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
    interface_to_element_map = {}
    external_interfaces_list = []
    probability_data = []
    AssetinSystem = []
    HazardinSystem = []
    VulnerabilityinSystem = []
    connections = []
    connections_mapped = []
    result_list = []
    total_elements = set()

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
        
        probability_of_exposure_value = get_attribute_value(internal_element, 'Probability of Exposure')
        probability_of_exposure = None
        if probability_of_exposure_value is not None:
            probability_of_exposure = probability_of_exposure_value
        else:
            probability_of_exposure = 0
        
        probability_of_impact_value = get_attribute_value(internal_element, 'Probability of Impact')
        probability_of_impact_vulnerability = None
        if probability_of_impact_value is not None:
            probability_of_impact_vulnerability = probability_of_impact_value
        else:
            probability_of_impact_vulnerability = 0

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
            'Probability of Failure': probability_of_failure,
            'Probability of Exposure': probability_of_exposure,
            'Probability of Impact' : probability_of_impact_vulnerability,
            'Probability of Mitigation' : probability_of_mitigation,
            'Probability of Human Error': probability_of_human_error,
            'RefBaseSystemUnitPath': ref_base_system_unit_path
        }
        
        if ref_base_system_unit_path.startswith ('AssetofICS/'):
            AssetinSystem.append(internal_element_data)
        elif ref_base_system_unit_path == 'HazardforSystem/Hazard':
            HazardinSystem.append(internal_element_data)
        elif ref_base_system_unit_path == 'VulnerabilityforSystem/Vulnerability':
            VulnerabilityinSystem.append(internal_element_data)
    
        probability_data.append(internal_element_data)
    
    for internal_element in root.findall(internalElementTag):
        external_interfaces = internal_element.findall(externalInterfaceTag)
        if len(external_interfaces) < 5:
            internal_element_id = internal_element.get('ID')
            internal_element_name = internal_element.get('Name')
            for external_interface in external_interfaces:
                external_interface_id = external_interface.get('ID')
                external_interface_name = external_interface.get('Name')
                external_interface_ref_base_class_path = external_interface.get('RefBaseClassPath')
#                if external_interface_ref_base_class_path != 'ConnectionBetnAssets/Network based':
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

    for connection in connections_mapped:
        from_element = connection['from']
        to_element = connection['to']
        total_elements.add(from_element)
        total_elements.add(to_element)
        connections_from_to[from_element].append(to_element)
        connections_to_from[to_element].append(from_element)

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


    root_nodes = [element for element in total_elements 
                if element not in connections_to_from or len(connections_to_from[element]) == 0]
    start_node = next(iter(root_nodes)) if root_nodes else None
    print ("Start node: ", start_node)

    end_nodes = [
        element for element in total_elements
        if element not in connections_from_to or len(connections_from_to[element]) == 0
    ]
    end_node = next(iter(end_nodes)) if end_nodes else None
    print("End node:", end_node)

    #check_probability_data(amldata)
    return probability_data, HazardinSystem, VulnerabilityinSystem, max_num_parents, total_elements, connections, connections_mapped, result_list, start_node, end_node

def generate_cpd_values_hazard(num_parents):
    cpd_values = [[0] * (2 ** num_parents) for _ in range(2)]
    for i in range(2 ** num_parents):
        num_ones = bin(i).count('1')
        cpd_values[0][i] = (num_parents - num_ones) / num_parents
        cpd_values[1][i] = 1 - cpd_values[0][i]
    return cpd_values

def generate_cpd_values_exposure(num_states, num_parents, max_num_parents, aml_data: AMLData, sap,
                                   matching_hazard_nodes=[], matching_vulnerability_nodes=[], matching_asset_nodes=[],
                                   hazard_node=False, vulnerability_node=False, asset_node=False):
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
        probability_of_exposure_for_node = matching_vulnerability_nodes[0]['Probability of Exposure']
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
        ref_base_for_node = matching_asset_nodes[0]['RefBaseSystemUnitPath']    
        if ref_base_for_node.startswith ('AssetOfICS/'):
            probability_of_failure_for_node = matching_asset_nodes[0]['Probability of Failure']

            # Calculate probability of failure based on connected vulnerabilities
            connections_from_to = defaultdict(list)

            for connection in aml_data.connections_mapped:
                from_element = connection['from']
                if matching_asset_nodes[0]['ID'] == from_element:
                    to_element = connection['to']
                    if re.match(r'^(V|\(V|\[V)\d', to_element):
                        connections_from_to[from_element].append(to_element)

            for asset, vulns in connections_from_to.items():
                num_vulns = len(vulns)

                sum_mitigation = 0.0  # Initialize sum for each asset

                for i in range(num_vulns):
                    matched = [element for element in aml_data.VulnerabilityinSystem if element['ID'] == vulns[i]]
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
            probability_of_human_error_for_node = matching_asset_nodes[0]['Probability of Human Error']
            pofhe = float(probability_of_human_error_for_node)
            cpd_values[0, 0] = pofhe
            cpd_values[1, 0] = 1 - pofhe
        else:
            probability_of_failure_for_node = matching_asset_nodes[0]['Probability of Failure']
            poff = float(probability_of_failure_for_node)
            cpd_values[0, 0] = poff
            cpd_values[1, 0] = 1 - poff

    cpd_values /= np.sum(cpd_values, axis=0)  # Normalize the CPD values
    return cpd_values.reshape((num_states, -1))

def generate_cpd_values_impact(node, num_states, num_parents, max_num_parents, result_list,
                                   matching_hazard_nodes=[], matching_vulnerability_nodes=[], matching_asset_nodes=[],
                                   hazard_node=False, vulnerability_node=False, asset_node=False):
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
        probability_of_impact_for_node = matching_vulnerability_nodes[0]['Probability of Impact'] * ( 1 - matching_vulnerability_nodes[0]['Probability of Mitigation'])
        pofi = float(probability_of_impact_for_node)
        #print (matching_vulnerability_nodes[0]['ID'], matching_vulnerability_nodes[0]['Probability of Impact'], pofi)
        if num_parents == 0:
            cpd_values[0, 0] = pofi
            cpd_values[1, 0] = 1 - pofi
        elif num_parents >= 1:
            cpd_values[0, :-1] = 1
            cpd_values[1, :-1] = 0
            cpd_values[0, -1] = pofi
            cpd_values[1, -1] = 1 - pofi
    
    elif asset_node:
        ref_base_for_node = matching_asset_nodes[0]['RefBaseSystemUnitPath']
        if ref_base_for_node.startswith ('AssetOfICS/'):
            probability_of_failure_for_node = matching_asset_nodes[0]['Probability of Failure']
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

def create_bbn_exposure(aml_data: AMLData, sap):
    probability_data = aml_data.probability_data
    HazardinSystem = aml_data.HazardinSystem
    VulnerabilityinSystem = aml_data.VulnerabilityinSystem
    max_num_parents = aml_data.max_num_parents
    total_elements = aml_data.total_elements
    connections = aml_data.connections
    connections_mapped = aml_data.connections_mapped
    result_list = aml_data.result_list

    cpds = {}
    cpd_values_list = []
    last_node = None
    matching_hazard_nodes = []
    matching_vulnerability_nodes = []
    matching_asset_nodes = []
    path_length_betn_nodes= []
    path_length_betn_nodes_final= []
    path_length_final_node = []

    bbn_exposure = DiscreteBayesianNetwork()
    connections = connections_mapped
    bbn_exposure.add_nodes_from(total_elements)
    bbn_exposure.add_edges_from([(connection['from'], connection['to']) for connection in connections])

    for node in bbn_exposure.nodes():
        num_parents = len(bbn_exposure.get_parents(node))
        num_states = 2  # Assuming binary states for each node
        matching_hazard_nodes = [element for element in HazardinSystem if element['ID'] == node]
        matching_vulnerability_nodes = [element for element in VulnerabilityinSystem if element['ID'] == node]
        matching_asset_nodes = [element for element in probability_data if element['ID'] == node]

        cpd_values = None

        if matching_hazard_nodes:
            cpd_values = generate_cpd_values_exposure(num_states, num_parents, max_num_parents, aml_data, sap, matching_hazard_nodes=matching_hazard_nodes, hazard_node=True)
        elif matching_vulnerability_nodes:
            cpd_values = generate_cpd_values_exposure(num_states, num_parents, max_num_parents, aml_data, sap, matching_vulnerability_nodes=matching_vulnerability_nodes, vulnerability_node=True)
        elif matching_asset_nodes:
            cpd_values = generate_cpd_values_exposure(num_states, num_parents, max_num_parents, aml_data, sap, matching_asset_nodes=matching_asset_nodes, asset_node=True)

        #print(f"[DEBUG] CPD values before normalization for node {node}: {cpd_values}")

        cpd = TabularCPD(variable=node, variable_card=num_states, values=cpd_values,
                        evidence=bbn_exposure.get_parents(node), evidence_card=[2] * num_parents)

        cpds[node] = cpd
        cpd_values_list.append((node, cpd_values.tolist(), cpd.variables, cpd.cardinality))
        
    bbn_exposure.add_cpds(*cpds.values())
    bbn_graph = bbn_exposure.to_markov_model()

    for element1 in HazardinSystem:
        node1=element1['ID']
        for element2 in result_list:
            node2=element2['Element']
            child_num = element2['Number of children']
            if node1 == node2:
                if child_num == 0:
                    last_node = node1

    print("\n[*] Last node in BBN:", last_node)

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
    
    return bbn_exposure

def create_bbn_impact(bbn_exposure, aml_data: AMLData):
    probability_data = aml_data.probability_data
    HazardinSystem = aml_data.HazardinSystem
    VulnerabilityinSystem = aml_data.VulnerabilityinSystem
    max_num_parents = aml_data.max_num_parents
    connections = aml_data.connections
    result_list = aml_data.result_list
    
    cpds = {}
    matching_hazard_nodes = []
    matching_vulnerability_nodes = []
    matching_asset_nodes = []

    bbn_impact = DiscreteBayesianNetwork()
    bbn_impact.add_edges_from([(connection['from'], connection['to']) for connection in connections])
 
    for node in bbn_impact.nodes():
        num_parents = len(bbn_exposure.get_parents(node))
        num_states = 2
        cpd_values = None
        
        matching_hazard_nodes = [element for element in HazardinSystem if element['ID'] == node]
        matching_vulnerability_nodes = [element for element in VulnerabilityinSystem if element['ID'] == node]
        matching_asset_nodes = [element for element in probability_data if element['ID'] == node]

        if matching_hazard_nodes:
            cpd_values = generate_cpd_values_impact(node, num_states, num_parents, max_num_parents, result_list=result_list, matching_hazard_nodes=matching_hazard_nodes, hazard_node=True)
        elif matching_vulnerability_nodes:
            cpd_values = generate_cpd_values_impact(node, num_states, num_parents, max_num_parents, result_list=result_list, matching_vulnerability_nodes=matching_vulnerability_nodes, vulnerability_node=True)
        elif matching_asset_nodes:
            cpd_values = generate_cpd_values_impact(node, num_states, num_parents, max_num_parents, result_list=result_list, matching_asset_nodes=matching_asset_nodes, asset_node=True)

        #print(f"[DEBUG] CPD values before normalization for node {node}: {cpd_values}")

        cpd = TabularCPD(variable=node, variable_card=num_states, values=cpd_values,
                        evidence=bbn_impact.get_parents(node), evidence_card=[2] * num_parents)
        cpds[node] = cpd

    bbn_impact.add_cpds(*cpds.values())

    return bbn_impact

def check_bbn_models(bbn_exposure, bbn_impact):
    print("[*] Checking BBN (Exposure) structure consistency:", bbn_exposure.check_model())
    print("[*] Checking BBN (Impact) structure consistency:", bbn_impact.check_model())

def plot_bbn(bbn):
    graph = nx.DiGraph()
    graph.add_nodes_from(bbn.nodes())
    graph.add_edges_from(bbn.edges())
    pos = nx.kamada_kawai_layout(graph, scale=2)
    nx.draw_networkx_nodes(graph, pos, node_color='lightblue', node_size=300)
    nx.draw_networkx_edges(graph, pos, arrows=True, arrowstyle='->', arrowsize=10)
    nx.draw_networkx_labels(graph, pos)
    plt.title("Bayesian Belief Network")
    plt.axis('off')
    plt.show()

def compute_risk_scores(inference_exposure, inference_impact, total_elements, start_node, end_node):
    for nodes in total_elements:
        if nodes == end_node:
            prob_failure = inference_exposure.query(variables=[nodes], evidence={start_node:1})
            print("[*] CPT (Exposure):\n", prob_failure)
            prob_impact = inference_impact.query(variables=[nodes], evidence={start_node:1})
            print("[*] CPT (Impact):\n", prob_impact)        
            cpd_prob = prob_failure.values
            cpd_impact = prob_impact.values
            print('--------------------------------------------------------')
            print("[*] Posterior probability of Exposure:", cpd_prob[0])
            print("[*] Posterior probability of Impact:", cpd_impact[0])
            risk_score = cpd_prob[0] * cpd_impact[0]
            print('[*] Risk score: {:.2f} %'.format(risk_score * 100))
            print('--------------------------------------------------------')
            if risk_score < 0.2:
                print('[----] CPS System is under NEGLIGIBLE risk (less than 20%)')
            elif 0.2 <= risk_score < 0.4:
                print('[*---] CPS System is under LOW risk (between 20% and 40%)')
            elif 0.4 <= risk_score < 0.6:
                print('[**--] CPS System is under MEDIUM risk (between 40% and 60%)')
            elif 0.6 <= risk_score < 0.8:
                print('[***-] CPS System is under HIGH risk (between 60% and 80%)')
            else:
                print('[****] CPS System is under CRITICAL risk (greater than 80%)')
        else:
            pass

def bbn_inference(aml_data: AMLData, sap, start_node):
    probability_data = aml_data.probability_data
    HazardinSystem = aml_data.HazardinSystem
    VulnerabilityinSystem = aml_data.VulnerabilityinSystem
    max_num_parents = aml_data.max_num_parents
    total_elements = aml_data.total_elements
    connections = aml_data.connections
    connections_mapped = aml_data.connections_mapped
    result_list = aml_data.result_list
 
    cpds = {}
    cpd_values_list = []
    last_node = None
    matching_hazard_nodes = []
    matching_vulnerability_nodes = []
    matching_asset_nodes = []
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
        matching_asset_nodes = [element for element in probability_data if element['ID'] == node]

        cpd_values = None

        if matching_hazard_nodes:
            cpd_values = generate_cpd_values_exposure(num_states, num_parents, max_num_parents, aml_data, sap, matching_hazard_nodes=matching_hazard_nodes, hazard_node=True)
        elif matching_vulnerability_nodes:
            cpd_values = generate_cpd_values_exposure(num_states, num_parents, max_num_parents, aml_data, sap, matching_vulnerability_nodes=matching_vulnerability_nodes, vulnerability_node=True)
        elif matching_asset_nodes:
            cpd_values = generate_cpd_values_exposure(num_states, num_parents, max_num_parents, aml_data, sap, matching_asset_nodes=matching_asset_nodes, asset_node=True)

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
        matching_asset_nodes = [element for element in probability_data if element['ID'] == node]

        if matching_hazard_nodes:
            cpd_values = generate_cpd_values_impact(node, num_states, num_parents, max_num_parents, result_list=result_list, matching_hazard_nodes=matching_hazard_nodes, hazard_node=True)
        elif matching_vulnerability_nodes:
            cpd_values = generate_cpd_values_impact(node, num_states, num_parents, max_num_parents, result_list=result_list, matching_vulnerability_nodes=matching_vulnerability_nodes, vulnerability_node=True)
        elif matching_asset_nodes:
            cpd_values = generate_cpd_values_impact(node, num_states, num_parents, max_num_parents, result_list=result_list, matching_asset_nodes=matching_asset_nodes, asset_node=True)

        cpd = TabularCPD(variable=node, variable_card=num_states, values=cpd_values,
                        evidence=bbn_exposure.get_parents(node), evidence_card=[2] * num_parents)

        cpds[node] = cpd
        cpd_values_list.append((node, cpd_values.tolist(), cpd.variables, cpd.cardinality))

    bbn_impact.add_cpds(*cpds.values())

    inference_exposure = VariableElimination(bbn_exposure)
    inference_impact = VariableElimination(bbn_impact)

    for nodes in total_elements:
        if nodes == last_node:
            values = [f"{element['ID']}: {element['Probability of Mitigation']}" for element in probability_data if element['ID'] in [f"V{j}" for j in range(1,12)]]
            prob_exposure = inference_exposure.query(variables=[nodes], evidence={start_node:1})
            prob_failure = inference_impact.query(variables=[nodes], evidence={start_node:1})
            cpd_prob = prob_exposure.values
            cpd_impact = prob_failure.values
            print(", ".join(values), ",", cpd_prob[0], ",", cpd_impact[0], ", {:.2f}%".format(cpd_prob[0] * cpd_impact[0] * 100))
            return cpd_prob[0], 1 - cpd_impact[0], cpd_prob[0] * cpd_impact[0] * 100
        else:
            pass

if __name__ == "__main__":
    env = Environment(*setup_environment(interactive=True))
    aml_data = AMLData(*process_AML_file(env.element_tree_root, env.t))

    bbn_exposure = create_bbn_exposure(aml_data, env.sap)
    bbn_impact = create_bbn_impact(bbn_exposure, aml_data)
    check_bbn_models(bbn_exposure, bbn_impact)

    inference_exposure = VariableElimination(bbn_exposure)
    inference_impact = VariableElimination(bbn_impact)

#    plot_bbn(bbn_exposure)

    compute_risk_scores(inference_exposure, inference_impact, aml_data.total_elements, aml_data.start_node, aml_data.end_node)
