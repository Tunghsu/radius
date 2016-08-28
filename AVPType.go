package radius

import (
	"strconv"
)

type AVPType uint8

const (
	//start rfc2865
	AVPTypeUserName                     AVPType = 1
	AVPTypeUserPassword                 AVPType = 2
	AVPTypeCHAPPassword                 AVPType = 3
	AVPTypeNASIPAddress                 AVPType = 4
	AVPTypeNASPort                      AVPType = 5
	AVPTypeServiceType                  AVPType = 6
	AVPTypeFramedProtocol               AVPType = 7
	AVPTypeFramedIPAddress              AVPType = 8  //8
	AVPTypeFramedIPNetmask              AVPType = 9  //9
	AVPTypeFramedRouting                AVPType = 10 //10
	AVPTypeFilterId                     AVPType = 11 //11
	AVPTypeFramedMTU                    AVPType = 12 //12
	AVPTypeFramedCompression            AVPType = 13 //13
	AVPTypeLoginIPHost                  AVPType = 14 //14
	AVPTypeLoginService                 AVPType = 15 //15
	AVPTypeLoginTCPPort                 AVPType = 16 //16
	AVPTypeReplyMessage                 AVPType = 18 //18
	AVPTypeCallbackNumber               AVPType = 19 //19
	AVPTypeCallbackId                   AVPType = 20 //20
	AVPTypeFramedRoute                  AVPType = 22 //22
	AVPTypeFramedIPXNetwork             AVPType = 23 //23
	AVPTypeState                        AVPType = 24 //24
	AVPTypeClass                        AVPType = 25 //25
	AVPTypeVendorSpecific               AVPType = 26
	AVPTypeSessionTimeout               AVPType = 27
	AVPTypeIdleTimeout                  AVPType = 28
	AVPTypeTerminationAction            AVPType = 29
	AVPTypeCalledStationId              AVPType = 30
	AVPTypeCallingStationId             AVPType = 31
	AVPTypeNASIdentifier                AVPType = 32
	AVPTypeProxyState                   AVPType = 33
	AVPTypeLoginLATService              AVPType = 34
	AVPTypeLoginLATNode                 AVPType = 35
	AVPTypeLoginLATGroup                AVPType = 36
	AVPTypeFramedAppleTalkLink          AVPType = 37
	AVPTypeFramedAppleTalkNetwork       AVPType = 38
	AVPTypeFramedAppleTalkZone          AVPType = 39
	AVPTypeAcctStatusType               AVPType = 40
	AVPTypeAcctDelayTime                AVPType = 41
	AVPTypeAcctInputOctets              AVPType = 42
	AVPTypeAcctOutputOctets             AVPType = 43
	AVPTypeAcctSessionId                AVPType = 44
	AVPTypeAcctAuthentic                AVPType = 45
	AVPTypeAcctSessionTime              AVPType = 46
	AVPTypeAcctInputPackets             AVPType = 47
	AVPTypeAcctOutputPackets            AVPType = 48
	AVPTypeAcctTerminateCause           AVPType = 49
	AVPTypeAcctMultiSessionId           AVPType = 50
	AVPTypeAcctLinkCount                AVPType = 51
	AVPTypeAcctInputGigawords           AVPType = 52 //52
	AVPTypeAcctOutputGigawords          AVPType = 53
	AVPTypeUnassigned1                  AVPType = 54
	AVPTypeEventTimestamp               AVPType = 55
	AVPTypeEgressVLANID                 AVPType = 56
	AVPTypeIngressFilters               AVPType = 57
	AVPTypeEgressVLANName               AVPType = 58
	AVPTypeUserPriorityTable            AVPType = 59 //59
	AVPTypeCHAPChallenge                AVPType = 60
	AVPTypeNASPortType                  AVPType = 61
	AVPTypePortLimit                    AVPType = 62
	AVPTypeLoginLATPort                 AVPType = 63 //end rfc2865 rfc 2866
	AVPTypeTunnelType                   AVPType = 64 //64
	AVPTypeTunnelMediumType             AVPType = 65
	AVPTypeTunnelClientEndpoint         AVPType = 66
	AVPTypeTunnelServerEndpoint         AVPType = 67
	AVPTypeAcctTunnelConnection         AVPType = 68
	AVPTypeTunnelPassword               AVPType = 69
	AVPTypeARAPPassword                 AVPType = 70
	AVPTypeARAPFeatures                 AVPType = 71
	AVPTypeARAPZoneAccess               AVPType = 72
	AVPTypeARAPSecurity                 AVPType = 73
	AVPTypeARAPSecurityData             AVPType = 74
	AVPTypePasswordRetry                AVPType = 75
	AVPTypePrompt                       AVPType = 76
	AVPTypeConnectInfo                  AVPType = 77
	AVPTypeConfigurationToken           AVPType = 78
	AVPTypeEAPMessage                   AVPType = 79
	AVPTypeMessageAuthenticator         AVPType = 80
	AVPTypeTunnelPrivateGroupID         AVPType = 81
	AVPTypeTunnelAssignmentID           AVPType = 82
	AVPTypeTunnelPreference             AVPType = 83
	AVPTypeARAPChallengeResponse        AVPType = 84
	AVPTypeAcctInterimInterval          AVPType = 85
	AVPTypeAcctTunnelPacketsLost        AVPType = 86
	AVPTypeNASPortId                    AVPType = 87
	AVPTypeFramedPool                   AVPType = 88
	AVPTypeCUI                          AVPType = 89
	AVPTypeTunnelClientAuthID           AVPType = 90
	AVPTypeTunnelServerAuthID           AVPType = 91
	AVPTypeNASFilterRule                AVPType = 92
	AVPTypeUnassigned                   AVPType = 93
	AVPTypeOriginatingLineInfo          AVPType = 94
	AVPTypeNASIPv6Address               AVPType = 95
	AVPTypeFramedInterfaceId            AVPType = 96
	AVPTypeFramedIPv6Prefix             AVPType = 97
	AVPTypeLoginIPv6Host                AVPType = 98
	AVPTypeFramedIPv6Route              AVPType = 99
	AVPTypeFramedIPv6Pool               AVPType = 100
	AVPTypeErrorCause                   AVPType = 101
	AVPTypeEAPKeyName                   AVPType = 102
	AVPTypeDigestResponse               AVPType = 103
	AVPTypeDigestRealm                  AVPType = 104
	AVPTypeDigestNonce                  AVPType = 105
	AVPTypeDigestResponseAuth           AVPType = 106
	AVPTypeDigestNextnonce              AVPType = 107
	AVPTypeDigestMethod                 AVPType = 108
	AVPTypeDigestURI                    AVPType = 109
	AVPTypeDigestQop                    AVPType = 110
	AVPTypeDigestAlgorithm              AVPType = 111
	AVPTypeDigestEntityBodyHash         AVPType = 112
	AVPTypeDigestCNonce                 AVPType = 113
	AVPTypeDigestNonceCount             AVPType = 114
	AVPTypeDigestUsername               AVPType = 115
	AVPTypeDigestOpaque                 AVPType = 116
	AVPTypeDigestAuthParam              AVPType = 117
	AVPTypeDigestAKAAuts                AVPType = 118
	AVPTypeDigestDomain                 AVPType = 119
	AVPTypeDigestStale                  AVPType = 120
	AVPTypeDigestHA1                    AVPType = 121
	AVPTypeSIPAOR                       AVPType = 122
	AVPTypeDelegatedIPv6Prefix          AVPType = 123
	AVPTypeMIP6FeatureVector            AVPType = 124
	AVPTypeMIP6HomeLinkPrefix           AVPType = 125
	AVPTypeOperatorName                 AVPType = 126
	AVPTypeLocationInformation          AVPType = 127
	AVPTypeLocationData                 AVPType = 128
	AVPTypeBasicLocationPolicyRules     AVPType = 129
	AVPTypeExtendedLocationPolicyRules  AVPType = 130
	AVPTypeLocationCapable              AVPType = 131
	AVPTypeRequestedLocationInfo        AVPType = 132
	AVPTypeFramedManagementProtocol     AVPType = 133
	AVPTypeManagementTransportProtectio AVPType = 134
	AVPTypeManagementPolicyId           AVPType = 135
	AVPTypeManagementPrivilegeLevel     AVPType = 136
	AVPTypePKMSSCert                    AVPType = 137
	AVPTypePKMCACert                    AVPType = 138
	AVPTypePKMConfigSettings            AVPType = 139
	AVPTypePKMCryptosuiteList           AVPType = 140
	AVPTypePKMSAID                      AVPType = 141
	AVPTypePKMSADescriptor              AVPType = 142
	AVPTypePKMAuthKey                   AVPType = 143
	AVPTypeDSLiteTunnelName             AVPType = 144
	AVPTypeMobileNodeIdentifier         AVPType = 145
	AVPTypeServiceSelection             AVPType = 146
	AVPTypePMIP6HomeLMAIPv6Address      AVPType = 147
	AVPTypePMIP6VisitedLMAIPv6Address   AVPType = 148
	AVPTypePMIP6HomeLMAIPv4Address      AVPType = 149
	AVPTypePMIP6VisitedLMAIPv4Address   AVPType = 150
	AVPTypePMIP6HomeHNPrefix            AVPType = 151
	AVPTypePMIP6VisitedHNPrefix         AVPType = 152
	AVPTypePMIP6HomeInterfaceID         AVPType = 153
	AVPTypePMIP6VisitedInterfaceID      AVPType = 154
	AVPTypePMIP6HomeIPv4HoA             AVPType = 155
	AVPTypePMIP6VisitedIPv4HoA          AVPType = 156
	AVPTypePMIP6HomeDHCP4ServerAddress  AVPType = 157
	AVPTypePMIP6VisitedDHCP4ServerAddre AVPType = 158
	AVPTypePMIP6HomeDHCP6ServerAddress  AVPType = 159
	AVPTypePMIP6VisitedDHCP6ServerAddre AVPType = 160
	AVPTypeUnassignedStart              AVPType = 161
	AVPTypeUnassignedEnd                AVPType = 191
	AVPTypeExperimentalStart            AVPType = 192
	AVPTypeExperimentalEnd              AVPType = 223
	AVPTypeImplementationSpecificStart  AVPType = 224
	AVPTypeImplementationSpecificEnd    AVPType = 240
	AVPTypeReservedStart                AVPType = 241
	AVPTypeReservedEnd                  AVPType = 254
)

func getTypeDesc(t AVPType) typeDesc {
	desc := typeMap[int(t)]
	if desc.decoder == nil {
		desc.decoder = avpBinary
	}
	if desc.name == "" {
		desc.name = "Unknow " + strconv.Itoa(int(t))
	}
	return desc
}

type typeDesc struct {
	name    string
	decoder func(p *Packet, typ AVPType, data []byte) (avp AVP, err error)
}

var typeMap = [256]typeDesc{
	AVPTypeUserName:                     {"UserName", avpString},
	AVPTypeUserPassword:                 {"UserPassword", avpPassword},
	AVPTypeCHAPPassword:                 {"CHAPPassword", avpBinary},
	AVPTypeNASIPAddress:                 {"NASIPAddress", avpIP},
	AVPTypeNASPort:                      {"NASPort", avpUint32},
	AVPTypeServiceType:                  {"ServiceType", avpUint32Enum(ServiceTypeEnum(0))},
	AVPTypeFramedProtocol:               {"FramedProtocol", avpUint32},
	AVPTypeFramedIPAddress:              {"FramedIPAddress", avpIP},
	AVPTypeFramedIPNetmask:              {"FramedIPNetmask", avpIP},
	AVPTypeFramedRouting:                {"FramedRouting", avpUint32},
	AVPTypeFilterId:                     {"FilterId", avpString},
	AVPTypeFramedMTU:                    {"FramedMTU", avpUint32},
	AVPTypeFramedCompression:            {"FramedCompression", avpUint32},
	AVPTypeLoginIPHost:                  {"LoginIPHost", avpIP},
	AVPTypeLoginService:                 {"LoginService", avpUint32},
	AVPTypeLoginTCPPort:                 {"LoginTCPPort", avpUint32},
	AVPTypeReplyMessage:                 {"ReplyMessage", avpString},
	AVPTypeCallbackNumber:               {"CallbackNumber", avpString},
	AVPTypeCallbackId:                   {"CallbackId", avpString},
	AVPTypeFramedRoute:                  {"FramedRoute", avpString},
	AVPTypeFramedIPXNetwork:             {"FramedIPXNetwork", avpIP},
	AVPTypeState:                        {"State", avpBinary},
	AVPTypeClass:                        {"Class", avpString},
	AVPTypeVendorSpecific:               {"VendorSpecific", avpVendorSpecific},
	AVPTypeSessionTimeout:               {"SessionTimeout", avpUint32},
	AVPTypeIdleTimeout:                  {"IdleTimeout", avpUint32},
	AVPTypeTerminationAction:            {"TerminationAction", avpUint32},
	AVPTypeCalledStationId:              {"CalledStationId", avpString},
	AVPTypeCallingStationId:             {"CallingStationId", avpString},
	AVPTypeNASIdentifier:                {"NASIdentifier", avpString},
	AVPTypeProxyState:                   {"ProxyState", avpString},
	AVPTypeLoginLATService:              {"LoginLATService", avpString},
	AVPTypeLoginLATNode:                 {"LoginLATNode", avpString},
	AVPTypeLoginLATGroup:                {"LoginLATGroup", avpString},
	AVPTypeFramedAppleTalkLink:          {"FramedAppleTalkLink", avpUint32},
	AVPTypeFramedAppleTalkNetwork:       {"FramedAppleTalkNetwork", avpUint32},
	AVPTypeFramedAppleTalkZone:          {"FramedAppleTalkZone", avpUint32},
	AVPTypeAcctStatusType:               {"AcctStatusType", avpUint32Enum(AcctStatusTypeEnum(0))},
	AVPTypeAcctDelayTime:                {"AcctDelayTime", avpUint32},
	AVPTypeAcctInputOctets:              {"AcctInputOctets", avpUint32},
	AVPTypeAcctOutputOctets:             {"AcctOutputOctets", avpUint32},
	AVPTypeAcctSessionId:                {"AcctSessionId", avpString},
	AVPTypeAcctAuthentic:                {"AcctAuthentic", avpUint32},
	AVPTypeAcctSessionTime:              {"AcctSessionTime", avpUint32},
	AVPTypeAcctInputPackets:             {"AcctInputPackets", avpUint32},
	AVPTypeAcctOutputPackets:            {"AcctOutputPackets", avpUint32},
	AVPTypeAcctTerminateCause:           {"AcctTerminateCause", avpUint32Enum(AcctTerminateCauseEnum(0))},
	AVPTypeAcctMultiSessionId:           {"AcctMultiSessionId", avpString},
	AVPTypeAcctLinkCount:                {"AcctLinkCount", avpUint32},
	AVPTypeAcctInputGigawords:           {"AcctInputGigawords", avpUint32},
	AVPTypeAcctOutputGigawords:          {"AcctOutputGigawords", avpUint32},
	AVPTypeUnassigned1:                  {"Unassigned1", avpBinary},
	AVPTypeEventTimestamp:               {"EventTimestamp", avpBinary},
	AVPTypeEgressVLANID:                 {"EgressVLANID", avpBinary},
	AVPTypeIngressFilters:               {"IngressFilters", avpBinary},
	AVPTypeEgressVLANName:               {"EgressVLANName", avpBinary},
	AVPTypeUserPriorityTable:            {"UserPriorityTable", avpBinary},
	AVPTypeCHAPChallenge:                {"CHAPChallenge", avpBinary},
	AVPTypeNASPortType:                  {"NASPortType", avpUint32Enum(NASPortTypeEnum(0))},
	AVPTypePortLimit:                    {"PortLimit", avpBinary},
	AVPTypeLoginLATPort:                 {"LoginLATPort", avpBinary},
	AVPTypeTunnelType:                   {"TunnelType", avpBinary},
	AVPTypeTunnelMediumType:             {"TunnelMediumType", avpBinary},
	AVPTypeTunnelClientEndpoint:         {"TunnelClientEndpoint", avpBinary},
	AVPTypeTunnelServerEndpoint:         {"TunnelServerEndpoint", avpBinary},
	AVPTypeAcctTunnelConnection:         {"AcctTunnelConnection", avpBinary},
	AVPTypeTunnelPassword:               {"TunnelPassword", avpBinary},
	AVPTypeARAPPassword:                 {"ARAPPassword", avpBinary},
	AVPTypeARAPFeatures:                 {"ARAPFeatures", avpBinary},
	AVPTypeARAPZoneAccess:               {"ARAPZoneAccess", avpBinary},
	AVPTypeARAPSecurity:                 {"ARAPSecurity", avpBinary},
	AVPTypeARAPSecurityData:             {"ARAPSecurityData", avpBinary},
	AVPTypePasswordRetry:                {"PasswordRetry", avpBinary},
	AVPTypePrompt:                       {"Prompt", avpBinary},
	AVPTypeConnectInfo:                  {"ConnectInfo", avpBinary},
	AVPTypeConfigurationToken:           {"ConfigurationToken", avpString},
	AVPTypeEAPMessage:                   {"EAPMessage", avpEapMessage},
	AVPTypeMessageAuthenticator:         {"MessageAuthenticator", avpBinary},
	AVPTypeTunnelPrivateGroupID:         {"TunnelPrivateGroupID", avpBinary},
	AVPTypeTunnelAssignmentID:           {"TunnelAssignmentID", avpBinary},
	AVPTypeTunnelPreference:             {"TunnelPreference", avpBinary},
	AVPTypeARAPChallengeResponse:        {"ARAPChallengeResponse", avpBinary},
	AVPTypeAcctInterimInterval:          {"AcctInterimInterval", avpBinary},
	AVPTypeAcctTunnelPacketsLost:        {"AcctTunnelPacketsLost", avpBinary},
	AVPTypeNASPortId:                    {"NASPortId", avpString},
	AVPTypeFramedPool:                   {"FramedPool", avpBinary},
	AVPTypeCUI:                          {"CUI", avpBinary},
	AVPTypeTunnelClientAuthID:           {"TunnelClientAuthID", avpBinary},
	AVPTypeTunnelServerAuthID:           {"TunnelServerAuthID", avpBinary},
	AVPTypeNASFilterRule:                {"NASFilterRule", avpBinary},
	AVPTypeUnassigned:                   {"Unassigned", avpBinary},
	AVPTypeOriginatingLineInfo:          {"OriginatingLineInfo", avpBinary},
	AVPTypeNASIPv6Address:               {"NASIPv6Address", avpBinary},
	AVPTypeFramedInterfaceId:            {"FramedInterfaceId", avpBinary},
	AVPTypeFramedIPv6Prefix:             {"FramedIPv6Prefix", avpBinary},
	AVPTypeLoginIPv6Host:                {"LoginIPv6Host", avpBinary},
	AVPTypeFramedIPv6Route:              {"FramedIPv6Route", avpBinary},
	AVPTypeFramedIPv6Pool:               {"FramedIPv6Pool", avpBinary},
	AVPTypeErrorCause:                   {"ErrorCause", avpBinary},
	AVPTypeEAPKeyName:                   {"EAPKeyName", avpBinary},
	AVPTypeDigestResponse:               {"DigestResponse", avpBinary},
	AVPTypeDigestRealm:                  {"DigestRealm", avpBinary},
	AVPTypeDigestNonce:                  {"DigestNonce", avpBinary},
	AVPTypeDigestResponseAuth:           {"DigestResponseAuth", avpBinary},
	AVPTypeDigestNextnonce:              {"DigestNextnonce", avpBinary},
	AVPTypeDigestMethod:                 {"DigestMethod", avpBinary},
	AVPTypeDigestURI:                    {"DigestURI", avpBinary},
	AVPTypeDigestQop:                    {"DigestQop", avpBinary},
	AVPTypeDigestAlgorithm:              {"DigestAlgorithm", avpBinary},
	AVPTypeDigestEntityBodyHash:         {"DigestEntityBodyHash", avpBinary},
	AVPTypeDigestCNonce:                 {"DigestCNonce", avpBinary},
	AVPTypeDigestNonceCount:             {"DigestNonceCount", avpBinary},
	AVPTypeDigestUsername:               {"DigestUsername", avpBinary},
	AVPTypeDigestOpaque:                 {"DigestOpaque", avpBinary},
	AVPTypeDigestAuthParam:              {"DigestAuthParam", avpBinary},
	AVPTypeDigestAKAAuts:                {"DigestAKAAuts", avpBinary},
	AVPTypeDigestDomain:                 {"DigestDomain", avpBinary},
	AVPTypeDigestStale:                  {"DigestStale", avpBinary},
	AVPTypeDigestHA1:                    {"DigestHA1", avpBinary},
	AVPTypeSIPAOR:                       {"SIPAOR", avpBinary},
	AVPTypeDelegatedIPv6Prefix:          {"DelegatedIPv6Prefix", avpBinary},
	AVPTypeMIP6FeatureVector:            {"MIP6FeatureVector", avpBinary},
	AVPTypeMIP6HomeLinkPrefix:           {"MIP6HomeLinkPrefix", avpBinary},
	AVPTypeOperatorName:                 {"OperatorName", avpBinary},
	AVPTypeLocationInformation:          {"LocationInformation", avpBinary},
	AVPTypeLocationData:                 {"LocationData", avpBinary},
	AVPTypeBasicLocationPolicyRules:     {"BasicLocationPolicyRules", avpBinary},
	AVPTypeExtendedLocationPolicyRules:  {"ExtendedLocationPolicyRules", avpBinary},
	AVPTypeLocationCapable:              {"LocationCapable", avpBinary},
	AVPTypeRequestedLocationInfo:        {"RequestedLocationInfo", avpBinary},
	AVPTypeFramedManagementProtocol:     {"FramedManagementProtocol", avpBinary},
	AVPTypeManagementTransportProtectio: {"ManagementTransportProtection", avpBinary},
	AVPTypeManagementPolicyId:           {"ManagementPolicyId", avpBinary},
	AVPTypeManagementPrivilegeLevel:     {"ManagementPrivilegeLevel", avpBinary},
	AVPTypePKMSSCert:                    {"PKMSSCert", avpBinary},
	AVPTypePKMCACert:                    {"PKMCACert", avpBinary},
	AVPTypePKMConfigSettings:            {"PKMConfigSettings", avpBinary},
	AVPTypePKMCryptosuiteList:           {"PKMCryptosuiteList", avpBinary},
	AVPTypePKMSAID:                      {"PKMSAID", avpBinary},
	AVPTypePKMSADescriptor:              {"PKMSADescriptor", avpBinary},
	AVPTypePKMAuthKey:                   {"PKMAuthKey", avpBinary},
	AVPTypeDSLiteTunnelName:             {"DSLiteTunnelName", avpBinary},
	AVPTypeMobileNodeIdentifier:         {"MobileNodeIdentifier", avpBinary},
	AVPTypeServiceSelection:             {"ServiceSelection", avpBinary},
	AVPTypePMIP6HomeLMAIPv6Address:      {"PMIP6HomeLMAIPv6Address", avpBinary},
	AVPTypePMIP6VisitedLMAIPv6Address:   {"PMIP6VisitedLMAIPv6Address", avpBinary},
	AVPTypePMIP6HomeLMAIPv4Address:      {"PMIP6HomeLMAIPv4Address", avpBinary},
	AVPTypePMIP6VisitedLMAIPv4Address:   {"PMIP6VisitedLMAIPv4Address", avpBinary},
	AVPTypePMIP6HomeHNPrefix:            {"PMIP6HomeHNPrefix", avpBinary},
	AVPTypePMIP6VisitedHNPrefix:         {"PMIP6VisitedHNPrefix", avpBinary},
	AVPTypePMIP6HomeInterfaceID:         {"PMIP6HomeInterfaceID", avpBinary},
	AVPTypePMIP6VisitedInterfaceID:      {"PMIP6VisitedInterfaceID", avpBinary},
	AVPTypePMIP6HomeIPv4HoA:             {"PMIP6HomeIPv4HoA", avpBinary},
	AVPTypePMIP6VisitedIPv4HoA:          {"PMIP6VisitedIPv4HoA", avpBinary},
	AVPTypePMIP6HomeDHCP4ServerAddress:  {"PMIP6HomeDHCP4ServerAddress", avpBinary},
	AVPTypePMIP6VisitedDHCP4ServerAddre: {"PMIP6VisitedDHCP4ServerAddress", avpBinary},
	AVPTypePMIP6HomeDHCP6ServerAddress:  {"PMIP6HomeDHCP6ServerAddress", avpBinary},
	AVPTypePMIP6VisitedDHCP6ServerAddre: {"PMIP6VisitedDHCP6ServerAddress", avpBinary},
	AVPTypeUnassignedStart:              {"UnassignedStart", avpBinary}, //161
	AVPTypeUnassignedEnd:                {"UnassignedEnd", avpBinary},
	AVPTypeExperimentalStart:            {"ExperimentalStart", avpBinary},
	AVPTypeExperimentalEnd:              {"ExperimentalEnd", avpBinary},
	AVPTypeImplementationSpecificStart:  {"ImplementationSpecificStart", avpBinary},
	AVPTypeImplementationSpecificEnd:    {"ImplementationSpecificEnd", avpBinary},
	AVPTypeReservedStart:                {"ReservedStart", avpBinary},
	AVPTypeReservedEnd:                  {"ReservedEnd", avpBinary},
}

func (a AVPType) String() string {
	return getTypeDesc(a).name
}
