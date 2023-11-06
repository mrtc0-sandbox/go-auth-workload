package sts

type AccessControlPolicy struct {
	AllowedSubject string `json:"allowed_subject"`
	FederatedBy    string `json:"federated_by"`
}

func NewAccessControlPolicy(allowedSubject, workloadIdentityProviderId string) *AccessControlPolicy {
	return &AccessControlPolicy{
		AllowedSubject: allowedSubject,
		FederatedBy:    workloadIdentityProviderId,
	}
}

func (a *AccessControlPolicy) IsAuthenticated(stsTokenContext *StsTokenContext) bool {
	if a.FederatedBy != stsTokenContext.FederatedBy {
		return false
	}

	if a.AllowedSubject != stsTokenContext.Payload.Subject {
		return false
	}

	return true
}
