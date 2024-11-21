import streamlit as st
from google_auth_oauthlib.flow import InstalledAppFlow
from googleapiclient.discovery import build

st.title("Email Dashboard")
st.write("This is a demo app for visualizing email data.")
