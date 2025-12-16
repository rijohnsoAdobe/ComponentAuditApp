import streamlit as st

st.set_page_config(page_title="Debug Root App", layout="wide")
st.write("DEBUG: app.py loaded at root")
st.write("DEBUG: st.query_params:", dict(st.query_params))
