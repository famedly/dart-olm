import re

def compute_error_function_name(func_name: str) -> str:
    """
    Choose the error function name based on substrings in the given function name.
    """
    func_name_lower = func_name.lower()
    if "inbound_group_session" in func_name_lower:
        return "olm_inbound_group_session_last_error"
    elif "outbound_group_session" in func_name_lower:
        return "olm_outbound_group_session_last_error"
    elif "account" in func_name_lower or "remove_one_time_keys" in func_name_lower:
        return "olm_account_last_error"
    elif "utility" in func_name_lower or "sha256" in func_name_lower or "ed25519_verify" in func_name_lower:
        return "olm_utility_last_error"
    elif "sas" in func_name_lower:
        return "olm_sas_last_error"
    elif "pk_sign" in func_name_lower:
        return "olm_pk_signing_last_error"
    elif "pk" in func_name_lower:
        return "olm_pk_decryption_last_error"
    elif "session" in func_name_lower or "encrypt" in func_name_lower or "decrypt" in func_name_lower:
        return "olm_session_last_error"
    else: # something we can look at incase there are new additions
        return "unmapped_error"

def get_first_param_name(header: str) -> str:
    """
    Extracts the first parameter name from the function header.
    Assumes the parameter list is within the first pair of parentheses.
    For example, for:
      int olm_clear_inbound_group_session(ffi.Pointer<ffi.NativeType> session, ...)
    returns "session".
    """
    m = re.search(r'\(([^)]*)\)', header)
    if m:
        params = m.group(1)
        param_list = [p.strip() for p in params.split(',') if p.strip()]
        if param_list:
            first_param = param_list[0]
            parts = first_param.split()
            return parts[-1]
    return ""


# get func which return int, start with olm_ and atleast have 1 argument
pattern_function = re.compile(
    r"(int\s+olm_[a-zA-Z0-9_]+\s*\([^)]*\)\s*\{)(.*?)(\n\s*\})",
    re.DOTALL
)

pattern_return = re.compile(r"return\s+(_olm_([a-zA-Z0-9_]+))\(([^)]*)\);")


def transform_function(match):
    header = match.group(1)
    body = match.group(2)
    closing = match.group(3)
    
    first_param = get_first_param_name(header)
    if not first_param:
        return match.group(0)
    
    def transform_return_closure(ret_match):
        """
        Transforms a return statement of the form:
          return _olm_<actual_function_name>(arguments);
        into:
          int result = _olm_<actual_function_name>(arguments);
          if (result == olm_error())
            throw_olm(<computed_error_func>(first_param));
          return result;
        """
        original_call = ret_match.group(1)
        func_name = ret_match.group(2)
        args = ret_match.group(3).strip()
        
        error_func = compute_error_function_name(func_name)
        
        new_lines = []
        new_lines.append(f"int result = {original_call}({args});")
        new_lines.append("if (result == olm_error())")
        new_lines.append(f"  throw_olm({error_func}({first_param}));")
        new_lines.append("return result;")
        return "\n".join(new_lines)
    
    new_body = pattern_return.sub(transform_return_closure, body)
    return header + new_body + closing

with open("lib/src/ffigen.dart", "r") as file:
    content = file.read()

new_content = pattern_function.sub(transform_function, content)

with open("lib/src/ffigen.dart", "w") as file:
    file.write(new_content)

print("Added error handling to ffigen.dart")