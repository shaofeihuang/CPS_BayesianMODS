#
 Project Repository: Bayesian and Multi-Objective Decision Support for Real-Time Cyber-Physical Incident Mitigation
This project repository provides resources and source code for performing Bayesian and multi-objective decision support for real-time cyber-physical incident mitigation. The BN structures capture probabilistic dependencies among CPS components, vulnerabilities, and hazards—enabling integrated assessment across cybersecurity, reliability, and safety dimensions.
The use of AutomationML, based on the CAEX (Computer Aided Engineering Exchange) schema, supports machine-readable and hierarchical representations of CPS assets and interdependencies. This facilitates model consistency, domain knowledge integration, and dynamic risk analysis.
---
##
 📂 Repository Contents
###
 
`
Reference Data Sheet.pdf
`
Includes data and formulae used in the project.
###
 
`
AML_BN_CPS.py
`
Performs BN-based CPS risk assessment on a generic AutomationML model. Computes probabilities of failure and system-level impact. Tested on Python 3.12.8.
###
 
`
AML_BN_Stuxnet.py
`
  
Applies the risk modelling framework to the Stuxnet cyber attack scenario. Parses 
`
Stuxnet.aml
`
 and generates BN outputs.
###
 
`
AML_BN_BlackEnergy.py
`
  
Implements BN-based analysis on the BlackEnergy malware attack scenario using the corresponding AutomationML file.
###
 
`
AML_BN_SolarPV.py
`
  
Demonstrates the methodology in a Solar PV attack context. Based on ForeScout's SUN:DOWN research:
  
[
https://www.forescout.com/research-labs/sun-down-a-dark-side-to-solar-energy-grids/
]
(
https://www.forescout.com/research-labs/sun-down-a-dark-side-to-solar-energy-grids/
)
###
 
`
AML_BN_CBTC.py
`
  
Analyses a railway Communication-Based Train Control (CBTC) attack scenario. Uses 
`
RailwayCBTC.aml
`
 to derive risk scores.
###
 
`
Optuna_Concurrent_SolarPV_3D.py
`
Proof-of-concept decision-support tool using multi-objective optimisation (via the Optuna library https://optuna.org)
###
 
`
utils.py
`
  
Contains shared utility functions for AutomationML file parsing and probability computation.
---
##
 📁 AutomationML Models
-
 
`
Generic_CPS.aml
`
: Canonical CPS configuration authored in AutomationML.
-
 
`
Stuxnet.aml
`
: Encodes assets and attack vectors observed in the Stuxnet case.
-
 
`
BlackEnergy.aml
`
: Captures structural elements and vulnerabilities from the BlackEnergy attack.
-
 
`
RailwayCBTC.aml
`
: Represents a CBTC-based railway cyber attack scenario.
---
##
 📄 Bayesian Network Model
-
 
`
Generic_CPS_BNN.xdsl
`
: BN model of a generic CPS system, developed using GeNIe Academic v5.0.
---
Feel free to open an issue for questions, improvements, or scenario extensions.

## License

MIT License

Copyright (c) 2025

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
