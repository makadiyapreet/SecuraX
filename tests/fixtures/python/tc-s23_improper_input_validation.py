import ast

def parse_safely(user_input):
    return ast.literal_eval(user_input)
