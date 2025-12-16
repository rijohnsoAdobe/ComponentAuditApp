import streamlit as st

st.set_page_config(page_title="Debug App", layout="wide")
st.title("Debug App – Query Param Test")

# Show st.query_params content
st.write("st.query_params:", dict(st.query_params))
