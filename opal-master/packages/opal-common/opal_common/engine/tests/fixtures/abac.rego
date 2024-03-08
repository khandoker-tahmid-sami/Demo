# Attribute-based access control (ABAC)


package hospital.ehr

# Default to deny
default allow = false

# Admins can perform any action
allow {
    user_is_admin
    input.location == data.users[input.user].location
    input.location == "NORWAY"
    admin_did_matches(input.user, input.did)
}

# Patients can read their EHR
allow {
    user_is_patient
    input.action == "read"
    input.type == "EHR"
    data.users[input.user].location == "NORWAY"
    patient_info_matches(input.user, input.did, input.location)
}

# Doctors can update EHR
allow {
    user_is_doctor
    input.action == "update"
    input.type == "EHR"
    data.users[input.user].location == "NORWAY"
}

# Helper Functions

# Check if user is an admin
user_is_admin {
    data.users[input.user].roles[_] == "admin"
}

# Check if user is a patient
user_is_patient {
    data.users[input.user].roles[_] == "patient"
}

# Check if user is a doctor
user_is_doctor {
    data.users[input.user].roles[_] == "doctor"
}

# Check if patient's DID and location match
patient_info_matches(user, did, location) {
    data.users[user].did == did
    data.users[user].location == location
}

# Check if admin's DID matches
admin_did_matches(user, did) {
    data.users[user].did == did
}



