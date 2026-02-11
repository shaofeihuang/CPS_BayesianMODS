'''
#######################################################################################################
BlackEnergy Risk Assessment using Bayesian Belief Networks (BBN) based on AutomationML Models
Author: Huang Shaofei
Last update: 2025-06-06
#######################################################################################################
'''

from utils import *

if __name__ == "__main__":
    env = Environment(*setup_environment(interactive=True))
    aml_data = AMLData(*process_AML_file(env.element_tree_root, env.t))

    bbn_exposure = create_bbn_exposure(aml_data, env.sap)
    bbn_impact = create_bbn_impact(bbn_exposure, aml_data)
    check_bbn_models(bbn_exposure, bbn_impact)

    inference_exposure = VariableElimination(bbn_exposure)
    inference_impact = VariableElimination(bbn_impact)

    #plot_bbn(bbn_exposure)

    valid_nodes = {"user", "v0", "v1", "v2", "v3", "v4", "v5", "v6", "v7", "v8", "v9", "v10"}
    source_node, target_node = find_shortest_path(bbn_exposure, valid_nodes, "User", "H5_Disable_Electrical_Supply")
    compute_risk_scores(inference_exposure, inference_impact, aml_data.total_elements, source_node, target_node)
