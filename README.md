# Cyber-Physical System (CPS) Risk Assessment using Bayesian Networks (BN) based on AutomationML Models

This repository contains code and resources for risk assessments using Bayesian Networks (BNs) specifically designed for Cyber-Physical Systems (CPS). The BNs are constructed using AutomationML models, and consider probabilities of CPS asset failures, cyber-physical vulnerabilities and cyber-physical hazards. This approach facilitates CPS risk assessments that integrate both cybersecurity, reliability, and safety aspects, as well as a standardised markup language to incorporate information and domain expert inputs into the model. This work takes inspiration from the findings by Bhosale et al. (2024) which can be found here: https://ieeexplore.ieee.org/stamp/stamp.jsp?arnumber=10623880

Adaptations of the approach as applied to other CPS examples are included in this repository.

## 1. AML_BN_CPS.py
This code was tested on Python 3.12.8. It analyses an AutomationML file to generate BNs and compute probabilities of occurence (of CPS system termination) and of severity/impact.

## 2. AML_BN_Stuxnet.py
This code demonstrates how this risk assessment approach can be applied to a real-world example - the Stuxnet attack. The code analyses the Stuxnet.aml file to generate BNs and compute a posterior risk score.

## 3. AML_BN_BlackEnergy.py
This code demonstrates how this risk assessment approach can be applied to a real-world example - the BlackEnergy attack. The code analyses the BlackEnergy.aml file to generate BNs and compute a posterior risk score.

## 4. AML_BN_SolarPV.py
This code demonstrates how this risk assessment approach can be applied to a Solar PV inverter attack scenario, based on ForeScout's SUN:DOWN research. (https://www.forescout.com/research-labs/sun-down-a-dark-side-to-solar-energy-grids/) The code analyses the SolarPV.aml file to generate BNs and compute a posterior risk score.

## 5. AML_BN_CBTC.py
This code demonstrates how this risk assessment approach can be applied to a Railway Communication Based Train Control (CBTC) attack scenario, The code analyses the RailwayCBTC.aml file to generate BNs and compute a posterior risk score.

## 6. Generic_CPS.aml
This is a markup file depicting a generic CPS based on the Automation Markup Language (AutomationML), edited using the AutomationML Editor. More information can be found here: https://www.automationml.org/

## 7. Stuxnet.aml
This is a markup file depicting the Stuxnet attack scenario based on the Automation Markup Language (AutomationML).

## 8. BlackEnergy.aml
This is a markup file depicting the BlackEnergy attack scenario based on the Automation Markup Language (AutomationML).

## 9. RailwayCBTC.aml
This is a markup file depicting the Railway CBTC attack scenario based on the Automation Markup Language (AutomationML).

## 10. Generic_CPS_BNN.xdsl
This is a representation of a generic CPS, edited using GeNIe Academic 5.0.
