# Risk Assessment for Generic Cyber-Physical Systems (CPS) using Bayesian Belief Networks (BBN) based on AutomationML Models

This repository contains code and resources for risk assessments using Bayesian Belief Networks (BBNs) specifically designed for generic Cyber-Physical Systems (CPS). The BBNs are constructed using AutomationML models, and consider probabilities of both cybersecurity vulnerabilities and physical hazards. This approach facilitates CPS risk assessments that integrate both cybersecurity and safety aspects, as well as a standardized markup language to incorporate information (such as threat intel) and domain expert inputs into the model. This work was inspired by Bhosale et al. (2024)'s paper which can be found here: https://ieeexplore.ieee.org/stamp/stamp.jsp?arnumber=10623880

An adaptation of the approach as applied to a real-world example - the Stuxnet Attack (Reference: https://spectrum.ieee.org/the-real-story-of-stuxnet) - is also included in this repository.


## 1. AML_BBN_CPS.py
This code was tested on Python 3.12.8. It analyses an AutomationML file to generate BBNs and compute probabilities of occurence (of CPS system termination) and of severity/impact. The code is adapted from the integrated safety and security risk assessment code developed by Bhosale, which can be referenced here: https://github.com/Pbhosale1991/AML-BBN-RA Changes were been made to the original code to improve its flow and clarity, user interface, and to fix bugs in the original code. A new function to identify shortest paths in the BBNs was also added.

## 2. AML_BBN_Stuxnet.py
This code demonstrates how this risk assessment approach can be applied to a real-world example - the Stuxnet attack. The code analyses the Stuxnet.aml file to generate BBNs and compute a risk score.

## 3. AML_BBN_BlackEnergy.py
This code demonstrates how this risk assessment approach can be applied to a real-world example - the BlackEnergy attack. The code analyses the BlackEnergy.aml file to generate BBNs and compute a risk score.

## 4. Generic_CPS.aml
This is a markup file depicting a generic CPS based on the Automation Markup Language (AutomationML), edited using the AutomationML Editor. More information can be found here: https://www.automationml.org/

## 5. Stuxnet.aml
This is a markup file depicting the Stuxnet attack scenario based on the Automation Markup Language (AutomationML), edited using the AutomationML Editor.

## 6. BlackEnergy.aml
This is a markup file depicting the BlackEnergy attack scenario based on the Automation Markup Language (AutomationML), edited using the AutomationML Editor.

## 7. Generic_CPS_BNN.xdsl
This is a representation of a generic CPS, edited using GeNIe Academic 5.0.
