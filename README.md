# Bayesian Belief Network (BBN) for Generic Cyber-Physical Systems (CPS)

This repository contains code and resources for constructing and analysing Bayesian Belief Networks (BBNs) specifically designed for generic Cyber-Physical Systems (CPS). The BBNs consider probabilities of both cybersecurity vulnerabilities and physical hazards, thereby facilitating CPS risk assessments that integrate both cybersecurity and safety aspects. This work was inspired by Bhosale et al. (2024)'s paper which can be found here: https://ieeexplore.ieee.org/stamp/stamp.jsp?arnumber=10623880

## 1. Generic_CPS.aml
This is a markup file depicting a generic CPS based on the Automation Markup Language (AutomationML). The More information can be found here: https://www.automationml.org/

## 2. Generic_CPS_BNN.xdsl
This is a representation of a generic CPS, edited using GeNIe Academic 5.0.

## 3. AML_BBN_CPS.py
This code based on Python analyses an AutomationML file to generate BBNs and compute probabilities of occurence (of CPS system termination) and of severity/impact. This is adapted from the integrated safety and security risk assessment code developed by Bhosale, which can be referenced here: https://github.com/Pbhosale1991/AML-BBN-RA

Changes were been made to the original code to improve clarity and correct bugs, as well as to include new functions to identify shortest paths.

