import streamlit as st
import pandas as pd
from cryptography.fernet import Fernet
import hashlib
from datetime import datetime, timedelta

# Security Configuration
SESSION_TIMEOUT = 1800  # 30 minutes
MAX_LOGIN_ATTEMPTS = 3

# Initialize Fernet cipher
key = st.secrets["ENCRYPTION_KEY"]
cipher = Fernet(key.encode())

def safe_display_date(date_value):
    """Optimized date display handler with enhanced NaN/NAT checking"""
    if pd.isna(date_value) or date_value is None:
        return "N/A"
    try:
        return date_value.strftime("%Y-%m-%d")
    except (AttributeError, ValueError):
        return str(date_value)

@st.cache_data(ttl=3600, show_spinner=False)
def load_secure_data():
    """Secure data loader with column validation"""
    try:
        with st.spinner("🔒 Decrypting database..."):
            with open("site_db_encrypted.xlsx", "rb") as f:
                decrypted = cipher.decrypt(f.read())

        @st.cache_data(ttl=3600, show_spinner=False)
        def convert_data(excel_data):
            df = pd.read_excel(excel_data, engine='openpyxl')
            df.columns = df.columns.str.upper().str.strip()
            
            # Validate and convert date columns
            date_cols = ["DATE MODIFIED", "PHYSICAL SITE RFS DATE", "LAST PM DATE"]
            existing_date_cols = [col for col in date_cols if col in df.columns]
            
            if not existing_date_cols:
                st.warning("No date columns found in dataset")
            else:
                for col in existing_date_cols:
                    df[col] = pd.to_datetime(df[col], errors='coerce', utc=True).dt.tz_localize(None)
                
                # Warn about missing date columns
                missing_dates = list(set(date_cols) - set(existing_date_cols))
                if missing_dates:
                    st.warning(f"Missing date columns: {', '.join(missing_dates)}")

            # Validate essential columns
            required_columns = ["SITE ID"]
            missing_required = [col for col in required_columns if col not in df.columns]
            
            if missing_required:
                st.error(f"Missing required columns: {', '.join(missing_required)}")
                st.stop()

            # Optimize dataframe structure
            df.set_index("SITE ID", inplace=True, drop=False)
            return df
        
        return convert_data(decrypted)
    
    except Exception as e:
        st.error(f"Data loading failed: {str(e)}")
        st.stop()

def check_auth():
    """Authentication state management"""
    if 'authenticated' not in st.session_state:
        st.session_state.update({
            'authenticated': False,
            'login_attempts': 0,
            'last_activity': datetime.now()
        })
    
    if st.session_state.authenticated:
        inactivity = (datetime.now() - st.session_state.last_activity).seconds
        if inactivity > SESSION_TIMEOUT:
            st.session_state.authenticated = False
            st.error("Session expired due to inactivity")
            st.rerun()
        else:
            st.session_state.last_activity = datetime.now()

def login_form():
    """Secure login interface"""
    with st.form("Login"):
        st.subheader("🔐 Site Information Portal")
        password = st.text_input("Enter access key", type="password")
        
        if st.form_submit_button("Authenticate"):
            hashed_input = hashlib.sha256(password.encode()).hexdigest()
            if hashed_input == st.secrets["ACCESS_HASH"]:
                st.session_state.update({
                    'authenticated': True,
                    'login_attempts': 0
                })
                st.rerun()
            else:
                st.session_state.login_attempts += 1
                if st.session_state.login_attempts >= MAX_LOGIN_ATTEMPTS:
                    st.error("Maximum attempts reached. System locked.")
                    st.stop()
                else:
                    remaining = MAX_LOGIN_ATTEMPTS - st.session_state.login_attempts
                    st.error(f"Invalid credentials ({remaining} attempts remaining)")

# Main Application Flow
check_auth()

if not st.session_state.authenticated:
    login_form()
    st.stop()

# Load data after authentication
try:
    df = load_secure_data()
    site_ids = df["SITE ID"].unique().tolist()
except KeyError as ke:
    st.error(f"Database validation failed: {str(ke)}")
    st.stop()

# Application Interface
st.title("📡 National Site Management System")

# Session timer
time_remaining = SESSION_TIMEOUT - (datetime.now() - st.session_state.last_activity).seconds
st.caption(f"Session active - Auto-logout in {time_remaining//60:02d}:{time_remaining%60:02d}")

# Sidebar Controls
with st.sidebar:
    st.header("Filters")
    selected_site = st.selectbox(
        "Select Site ID",
        options=site_ids,
        help="Search for site by ID"
    )
    
    # Dynamic field groups based on available columns
    all_fields = {
        "Location": ["LATITUDE", "LONGITUDE", "REGION", "CITY/PROVINCE", "AREA"],
        "Technical Specs": ["SITE TYPE", "TOWER TYPE", "TOWER HEIGHT (METER)", 
                          "PHYSICAL SITE RFS DATE", "5G CODE", "LTE CODE"],
        "Device Info": ["OLT", "FTTA", "OSN", "OTN", "IIB", "HASHANTOUK 2G/3G"],
        "Power Systems": ["MAINS POWER", "PRIMARY GENSET (YES/NO)", 
                        "STANDBY GENERATOR ENGINE MODEL/KVA", "DC SYSTEM 1 BRAND"],
        "Security": ["SHELTER KEY", "MAIN KEY", "ACCESS PROCEDURE", "POC NUMBER"]
    }
    
    # Filter out missing columns
    available_fields = {}
    for group, fields in all_fields.items():
        available_fields[group] = [f for f in fields if f in df.columns]
    
    selected_fields = st.multiselect(
        "Select information to display",
        options=[item for group in available_fields.values() for item in group],
        default=["SITE TYPE", "LATITUDE", "LONGITUDE", "OLT", "FTTA"],
        format_func=lambda x: x.title().replace("_", " ")
    )

# Load site data
@st.cache_data(show_spinner=False)
def get_site_data(site_id):
    try:
        return df.loc[site_id]
    except KeyError:
        st.error(f"Site {site_id} not found")
        st.stop()

with st.spinner("Loading site information..."):
    result = get_site_data(selected_site)

# Location Map
if "LATITUDE" in selected_fields and "LONGITUDE" in selected_fields:
    with st.expander("🌍 Location Map", expanded=True):
        try:
            st.map(pd.DataFrame({
                "lat": [result["LATITUDE"]],
                "lon": [result["LONGITUDE"]]
            }), zoom=12)
        except KeyError:
            st.warning("Coordinates not available")

# Site Overview
with st.container():
    cols = st.columns(2)
    with cols[0]:
        st.subheader(f"Site Overview: {selected_site}")
        st.metric("Last Modified", safe_display_date(result.get("DATE MODIFIED")))
        st.metric("Site Type", result.get("SITE TYPE", "N/A"))
        
    with cols[1]:
        st.subheader("Technical Details")
        tech_fields = [f for f in selected_fields if f in available_fields["Technical Specs"]]
        for field in tech_fields:
            st.write(f"**{field.title()}:** {result.get(field, 'N/A')}")

# Device Information - Updated Section
if any(f in selected_fields for f in available_fields["Device Info"]):
    st.divider()
    with st.expander("📡 Device Information", expanded=True):
        device_data = {
            "OLT": result.get("OLT", pd.NA),
            "FTTA": result.get("FTTA", pd.NA),
            "OSN": result.get("OSN", pd.NA),
            "OTN": result.get("OTN", pd.NA),
            "IIB": result.get("IIB", pd.NA),
            "2G/3G": result.get("HASHANTOUK 2G/3G", pd.NA)
        }
        
        # Create 3 columns with custom spacing
        col1, col2, col3 = st.columns([1,1,1])
        
        with col1:
            for device in ["OLT", "FTTA"]:
                value = device_data[device]
                st.markdown(f"""
                <div style="margin: 5px 0; padding: 8px; background-color: #f8f9fa; border-radius: 5px;">
                    <p style="margin: 0; font-size: 14px; font-weight: 600;">{device}</p>
                    <p style="margin: 0; font-size: 13px; color: #333; word-wrap: break-word;">
                        {value if not pd.isna(value) else 'Not Installed'}
                    </p>
                </div>
                """, unsafe_allow_html=True)
        
        with col2:
            for device in ["OSN", "OTN"]:
                value = device_data[device]
                st.markdown(f"""
                <div style="margin: 5px 0; padding: 8px; background-color: #f8f9fa; border-radius: 5px;">
                    <p style="margin: 0; font-size: 14px; font-weight: 600;">{device}</p>
                    <p style="margin: 0; font-size: 13px; color: #333; word-wrap: break-word;">
                        {value if not pd.isna(value) else 'Not Installed'}
                    </p>
                </div>
                """, unsafe_allow_html=True)
        
        with col3:
            for device in ["IIB", "2G/3G"]:
                value = device_data[device]
                st.markdown(f"""
                <div style="margin: 5px 0; padding: 8px; background-color: #f8f9fa; border-radius: 5px;">
                    <p style="margin: 0; font-size: 14px; font-weight: 600;">{device}</p>
                    <p style="margin: 0; font-size: 13px; color: #333; word-wrap: break-word;">
                        {value if not pd.isna(value) else 'Not Installed'}
                    </p>
                </div>
                """, unsafe_allow_html=True)

# Security Information
if any(f in selected_fields for f in available_fields["Security"]):
    st.divider()
    with st.expander("🔑 Security Details", expanded=True):
        security_fields = [f for f in available_fields["Security"] if f in selected_fields]
        cols = st.columns(2)
        for i, field in enumerate(security_fields):
            with cols[i % 2]:
                st.write(f"**{field.title()}:** {result.get(field, 'N/A')}")

# Power Systems
if any(f in selected_fields for f in available_fields["Power Systems"]):
    st.divider()
    with st.expander("🔋 Power Systems", expanded=True):
        power_fields = [f for f in selected_fields if f in available_fields["Power Systems"]]
        cols = st.columns(2)
        for i, field in enumerate(power_fields):
            with cols[i % 2]:
                st.write(f"**{field.title()}:** {result.get(field, 'N/A')}")