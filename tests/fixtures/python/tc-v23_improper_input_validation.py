def calculate_expression(user_input):
    # Vulnerable: arbitrary code execution via eval
    return eval(user_input)
