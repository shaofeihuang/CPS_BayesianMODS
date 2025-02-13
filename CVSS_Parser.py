def parse_cvss(cvss_input):
    # Split the CVSS input into components
    components = cvss_input.split('/')

    # Define the metric values
    metrics = {
        'AV': {'N': 0.85, 'A': 0.62, 'L': 0.55, 'P': 0.2},
        'AC': {'L': 0.77, 'H': 0.44},
        'PR': {'N': 0.85, 'L': 0.62, 'H': 0.27},
        'UI': {'N': 0.85, 'R': 0.62},
        'S': {'U': 1.0, 'C': 1.0},
        'C': {'H': 0.56, 'L': 0.22, 'N': 0.0},
        'I': {'H': 0.56, 'L': 0.22, 'N': 0.0},
        'A': {'H': 0.56, 'L': 0.22, 'N': 0.0}
    }

    # Extract and map the metric values from the input
    values = {metric.split(':')[0]: metric.split(':')[1] for metric in components[1:]}
    AV = metrics['AV'][values['AV']]
    AC = metrics['AC'][values['AC']]
    PR = metrics['PR'][values['PR']]
    UI = metrics['UI'][values['UI']]
    C = metrics['C'][values['C']]
    I = metrics['I'][values['I']]
    A = metrics['A'][values['A']]

    # Compute P(N)vuln and S(N)vuln
    P_Nvuln = AV * AC * PR * UI
    S_Nvuln = 1 - ((1 - C) * (1 - I) * (1 - A))

    return P_Nvuln, S_Nvuln

# Prompt the user for CVSS input
cvss_input = input("Enter CVSS string: ")
P_Nvuln, S_Nvuln = parse_cvss(cvss_input)
print(f"P(N)vuln: {P_Nvuln:.4f}")
print(f"S(N)vuln: {S_Nvuln:.4f}")
