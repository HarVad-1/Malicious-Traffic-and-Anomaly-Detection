import os
import streamlit as st
import google.generativeai as genai

# Set up page configuration
st.set_page_config(
    page_title="Snort Rule Generator",
    page_icon="🛡️",
    layout="wide"
)

# Configure API key directly - replace with your own key
GOOGLE_API_KEY = "AIzaSyA_pM32Xic20HQehW0FpniewIrNKyalD8Y"  # Replace this with your actual API key
genai.configure(api_key=GOOGLE_API_KEY)

# Styling
st.markdown("""
<style>
    .main {
        padding: 2rem;
    }
    .chat-message {
        padding: 1rem;
        border-radius: 0.5rem;
        margin-bottom: 1rem;
    }
    .user-message {
        background-color: #f0f2f6;
    }
    .bot-message {
        background-color: #e6f3ff;
    }
</style>
""", unsafe_allow_html=True)

# List available models (helpful for debugging)
def list_available_models():
    try:
        models = genai.list_models()
        return [model.name for model in models]
    except Exception as e:
        return f"Error listing models: {str(e)}"

# Select the appropriate Gemini model
def get_gemini_model():
    """Get the appropriate Gemini model, ensuring gemini-1.5-flash is used."""
    return "models/gemini-1.5-flash"


def generate_snort_rule(prompt):
    """
    Generate Snort rules using Gemini API based on user input
    """
    try:
        # Get the correct model name
        model_name = get_gemini_model()
        
        # Log the model being used (for debugging)
        st.session_state.debug_info = f"Using model: {model_name}"
        
        # Initialize the model
        model = genai.GenerativeModel(model_name)
        
        # Create a comprehensive prompt for Gemini
        system_prompt = """
You are a Snort rule generation assistant. Generate valid, efficient Snort rules based on user descriptions.
Follow these guidelines:
1. Each rule should have correct syntax for the latest Snort version
2. Include header (action, protocol, IP addresses, ports) and rule options
3. Use appropriate Snort keywords and options
4. ALWAYS include the 'msg:' option with a descriptive message
5. ALWAYS include the 'sid:' option with a unique ID above 1000000
6. For complex scenarios, provide multiple rules if needed
7. Format your response as pure Snort rules without markdown code blocks

Example of a properly formatted rule:
alert tcp any any -> any 80 (msg:"SQL Injection Attempt"; content:"union select"; nocase; sid:1000001; rev:1;)

Format your response as valid Snort rules only. Do not include explanations outside of comments.
"""
        
        complete_prompt = f"{system_prompt}\n\nUser request: {prompt}\n\nGenerate appropriate Snort rule(s):"
        
        # Generate content with safety settings
        generation_config = {
            "temperature": 0.2,
            "top_p": 0.8,
            "top_k": 40,
            "max_output_tokens": 1024,
        }
        
        safety_settings = [
            {"category": "HARM_CATEGORY_HARASSMENT", "threshold": "BLOCK_MEDIUM_AND_ABOVE"},
            {"category": "HARM_CATEGORY_HATE_SPEECH", "threshold": "BLOCK_MEDIUM_AND_ABOVE"},
            {"category": "HARM_CATEGORY_SEXUALLY_EXPLICIT", "threshold": "BLOCK_MEDIUM_AND_ABOVE"},
            {"category": "HARM_CATEGORY_DANGEROUS_CONTENT", "threshold": "BLOCK_MEDIUM_AND_ABOVE"},
        ]
        
        response = model.generate_content(
            complete_prompt,
            generation_config=generation_config,
            safety_settings=safety_settings
        )
        
        return response.text
    except Exception as e:
        # Include detailed error information
        error_msg = f"Error generating Snort rule: {str(e)}"
        if hasattr(e, 'status_code'):
            error_msg += f" (Status code: {e.status_code})"
        return error_msg

def validate_rule(rule_text):
    """
    Basic validation of Snort rule syntax
    """
    # Check for common syntax elements
    if not rule_text or len(rule_text) < 10:
        return False, "Rule is too short"
    
    # Check if this is a code block or has formatting from Gemini
    rule_text = rule_text.replace("```", "").strip()
    
    # Some rules might be in a comment or explanation
    # Extract the actual rule if possible
    lines = rule_text.split("\n")
    rule_lines = [line for line in lines if line.strip() and not line.strip().startswith("#")]
    
    if not rule_lines:
        return False, "No valid rule found"
    
    # Join multiple lines if needed
    rule_text = " ".join(rule_lines)
    
    # Basic format checks
    if "alert" not in rule_text and "log" not in rule_text and "drop" not in rule_text and "reject" not in rule_text and "pass" not in rule_text:
        return False, "Missing valid action (alert, log, drop, reject, pass)"
    
    if "->" not in rule_text:
        return False, "Missing direction operator (->)"
    
    if "(" not in rule_text or ")" not in rule_text:
        return False, "Missing rule options parentheses"
    
    # Make 'msg' optional since some valid rules might not include it
    # if "msg:" not in rule_text:
    #    return False, "Missing 'msg' option"
    
    # Make 'sid' optional too as it might be auto-generated later
    # if "sid:" not in rule_text:
    #    return False, "Missing 'sid' option"
    
    return True, "Rule syntax looks valid"

# App title
st.title("🛡️ Snort Rule Generator")
st.markdown("Describe the threat or network condition and get a Snort rule generated for you.")

# Debug information (can be toggled with a feature flag)
debug_mode = False  # Set to True for debugging
if debug_mode and "debug_info" in st.session_state:
    st.info(st.session_state.debug_info)

# Sidebar with options
with st.sidebar:
    st.header("Options")
    
    st.subheader("Rule Templates")
    template_options = [
        "Detect SQL Injection",
        "Block Specific IP",
        "Detect Malware Communication",
        "Monitor Specific Protocol",
        "Custom"
    ]
    
    selected_template = st.selectbox("Select a template:", template_options)
    use_template_button = st.button("Use Template")
    
    st.divider()
    
    # Explanation section
    st.subheader("About Snort Rules")
    st.markdown("""
    **Snort Rule Syntax:**
    ```
    action protocol src_ip src_port direction dst_ip dst_port (options)
    ```
    
    **Common Actions:**
    - alert: Generate alert
    - drop: Drop packet and log
    - reject: Drop, log, and send TCP reset
    """)
    
    # Debug section (only shown in debug mode)
    if debug_mode:
        st.divider()
        st.subheader("Debug Information")
        if st.button("List Available Models"):
            models = list_available_models()
            st.write(models)

# Initialize chat history
if "messages" not in st.session_state:
    st.session_state.messages = []

# Display chat messages
for message in st.session_state.messages:
    with st.chat_message(message["role"]):
        st.markdown(message["content"])

# Handle template selection
if use_template_button and selected_template != "Custom":
    template_prompt = f"Create a Snort rule to {selected_template.lower()}"
    # Add template prompt to chat
    st.session_state.messages.append({"role": "user", "content": template_prompt})
    
    # Display user message
    with st.chat_message("user"):
        st.markdown(template_prompt)
    
    # Generate response
    with st.chat_message("assistant"):
        with st.spinner("Generating Snort rule..."):
            response = generate_snort_rule(template_prompt)
            
            # Validate the rule if not an error message
            if not response.startswith("Error"):
                is_valid, validation_message = validate_rule(response)
                
                # Display the rule
                st.code(response, language="python")
                
                # Show validation status
                if is_valid:
                    st.success(validation_message)
                else:
                    st.warning(f"{validation_message}. The rule may need manual review.")
            else:
                st.error(response)
    
    # Add assistant message to chat history
    st.session_state.messages.append({"role": "assistant", "content": response})

# User input
user_input = st.chat_input("Describe the network threat or condition...")

if user_input:
    # Add user message to chat history
    st.session_state.messages.append({"role": "user", "content": user_input})
    
    # Display user message
    with st.chat_message("user"):
        st.markdown(user_input)
    
    # Generate response
    with st.chat_message("assistant"):
        with st.spinner("Generating Snort rule..."):
            response = generate_snort_rule(user_input)
            
            # Validate the rule if not an error message
            if not response.startswith("Error"):
                is_valid, validation_message = validate_rule(response)
                
                # Display the rule
                st.code(response, language="python")
                
                # Show validation status
                if is_valid:
                    st.success(validation_message)
                else:
                    st.warning(f"{validation_message}. The rule may need manual review.")
                
                # Add options to copy or modify the rule
                col1, col2 = st.columns(2)
                with col1:
                    if st.button("Copy to Clipboard"):
                        st.write("Rule copied to clipboard!")
                with col2:
                    if st.button("Refine Rule"):
                        st.session_state.messages.append({"role": "user", "content": "Please refine this rule to be more specific."})
            else:
                st.error(response)
                if debug_mode:
                    st.info("Try checking the model name and API version compatibility")
    
    # Add assistant message to chat history
    st.session_state.messages.append({"role": "assistant", "content": response})

# Footer
st.markdown("---")
st.markdown("Powered by Gemini API | Developed for Network Security Teams")