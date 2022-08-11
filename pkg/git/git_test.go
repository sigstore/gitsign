// Copyright 2022 The Sigstore Authors
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package git

import "testing"

const (
	// These are real commit values generated in a test repo that were manually verified.

	// Rekor index: 2802961
	tagBody = `object 040b9af339e69d18848b7bbe05cb27ee42bb0161
type commit
tag signed-tag2
tagger Billy Lynch <billy@chainguard.dev> 1656531453 -0400

asdf
`
	tagSig = `-----BEGIN SIGNED MESSAGE-----
MIIEBQYJKoZIhvcNAQcCoIID9jCCA/ICAQExDTALBglghkgBZQMEAgEwCwYJKoZI
hvcNAQcBoIICpjCCAqIwggIooAMCAQICFGc8V7+B2VlJeFLpglonkbyb2kVeMAoG
CCqGSM49BAMDMDcxFTATBgNVBAoTDHNpZ3N0b3JlLmRldjEeMBwGA1UEAxMVc2ln
c3RvcmUtaW50ZXJtZWRpYXRlMB4XDTIyMDYyOTE5MzczOVoXDTIyMDYyOTE5NDcz
OVowADBZMBMGByqGSM49AgEGCCqGSM49AwEHA0IABP8JBFjhGqQsQCBmZqyuSHcG
KZpDDRdpq7cl8Bhwuvu9A2bDz0gcuA/Nv18fKtikguBw6YBmEPi8S/YMYgMctVyj
ggFHMIIBQzAOBgNVHQ8BAf8EBAMCB4AwEwYDVR0lBAwwCgYIKwYBBQUHAwMwHQYD
VR0OBBYEFMhi60DZPBYkwhDEuiltjyvxYYTDMB8GA1UdIwQYMBaAFN/T6c9WJBGW
+ajY6ShVosYuGGQ/MCIGA1UdEQEB/wQYMBaBFGJpbGx5QGNoYWluZ3VhcmQuZGV2
MCwGCisGAQQBg78wAQEEHmh0dHBzOi8vZ2l0aHViLmNvbS9sb2dpbi9vYXV0aDCB
iQYKKwYBBAHWeQIEAgR7BHkAdwB1AAhgkvAoUv9oRdHRayeEnEVnGKwWPcM40m3m
vCIGNm9yAAABgbD4HlAAAAQDAEYwRAIgON4g6BzdFgOIcCFk+8EXKpEw1XD0/DZ2
7gcb9Q/Jeg0CIGozxLGJS71uA2OU3JD6pGWCdnpYVsiG44/Em5w34SHmMAoGCCqG
SM49BAMDA2gAMGUCMQDjLNl6Zaj5HbfLqqUvWNgz/R1VoQ3QG88kzu3GY0PodO8K
QDcgt8bcGXzEdKkSFg4CMHIkGGLrG3bOYsjyIqZxiO6ess1jJxsFnM+GzvjwNRJk
eWF9g96u/pNN8KA5VhveljGCASUwggEhAgEBME8wNzEVMBMGA1UEChMMc2lnc3Rv
cmUuZGV2MR4wHAYDVQQDExVzaWdzdG9yZS1pbnRlcm1lZGlhdGUCFGc8V7+B2VlJ
eFLpglonkbyb2kVeMAsGCWCGSAFlAwQCAaBpMBgGCSqGSIb3DQEJAzELBgkqhkiG
9w0BBwEwHAYJKoZIhvcNAQkFMQ8XDTIyMDYyOTE5MzczOVowLwYJKoZIhvcNAQkE
MSIEINZzCK5apWIVIKK26tVflr6zNoFkJm8SXQC5T65qwF1BMAoGCCqGSM49BAMC
BEcwRQIgfAl7Elc0DB8UEMOXo3ZxKmN7zTrMO/tvhu1Himgc9IYCIQCxf06wWHVw
YKHxU2tY8MNGomLVk0LyA/QaHQnoo34t8A==
-----END SIGNED MESSAGE-----
`
	tagSHA = "ed092bb8688d6e37185bcdb58900940703c1a292"

	// Rekor index: 2801760
	commitBody = `tree b333504b8cf3d9c314fed2cc242c5c38e89534a5
parent 2dc0ab59d7f0a7a62423bd181d9e2ab3adb7b56d
author Billy Lynch <billy@chainguard.dev> 1656524971 -0400
committer Billy Lynch <billy@chainguard.dev> 1656524971 -0400

foo
`
	commitSig = `-----BEGIN SIGNED MESSAGE-----
MIIEBwYJKoZIhvcNAQcCoIID+DCCA/QCAQExDTALBglghkgBZQMEAgEwCwYJKoZI
hvcNAQcBoIICqDCCAqQwggIqoAMCAQICFHtMvZZL50P5bLkgDxwMf2MN4jdAMAoG
CCqGSM49BAMDMDcxFTATBgNVBAoTDHNpZ3N0b3JlLmRldjEeMBwGA1UEAxMVc2ln
c3RvcmUtaW50ZXJtZWRpYXRlMB4XDTIyMDYyOTE3NDkzNFoXDTIyMDYyOTE3NTkz
NFowADBZMBMGByqGSM49AgEGCCqGSM49AwEHA0IABNf9io+JonCZhwe/dSkSoJ/Y
eRun8C7xhPVF3FhoPnPVWdywaAEIkniA2WSHXLHt5aQN/08bV65haMZA/Luhmhaj
ggFJMIIBRTAOBgNVHQ8BAf8EBAMCB4AwEwYDVR0lBAwwCgYIKwYBBQUHAwMwHQYD
VR0OBBYEFGzhjCzFUI0caspJJfD4bToYxfDhMB8GA1UdIwQYMBaAFN/T6c9WJBGW
+ajY6ShVosYuGGQ/MCIGA1UdEQEB/wQYMBaBFGJpbGx5QGNoYWluZ3VhcmQuZGV2
MCwGCisGAQQBg78wAQEEHmh0dHBzOi8vZ2l0aHViLmNvbS9sb2dpbi9vYXV0aDCB
iwYKKwYBBAHWeQIEAgR9BHsAeQB3AAhgkvAoUv9oRdHRayeEnEVnGKwWPcM40m3m
vCIGNm9yAAABgbCVKBkAAAQDAEgwRgIhAJHJalxdErw5icNqfgWtyrv75XGXxAZz
F/J4b7B8ikQAAiEAj8g8ZiSIGmePmES19Y/yFeGj6Fz0NGE2Rk5uJdKyAGEwCgYI
KoZIzj0EAwMDaAAwZQIxAKpQFL9D5s1YVEmNWBoEQ1oo6gBESGhd5L1Kcdq52Ltt
KWXKKB7tpVRwC0lfof2ILgIwU1LTaKeKWb0vToMY9InoS2+hAVljbEh3oxKm/JoX
hiRx2GiDe2OyLCs76/kbH6C/MYIBJTCCASECAQEwTzA3MRUwEwYDVQQKEwxzaWdz
dG9yZS5kZXYxHjAcBgNVBAMTFXNpZ3N0b3JlLWludGVybWVkaWF0ZQIUe0y9lkvn
Q/lsuSAPHAx/Yw3iN0AwCwYJYIZIAWUDBAIBoGkwGAYJKoZIhvcNAQkDMQsGCSqG
SIb3DQEHATAcBgkqhkiG9w0BCQUxDxcNMjIwNjI5MTc0OTM0WjAvBgkqhkiG9w0B
CQQxIgQgSbThfvXoc6INDxPzRtlUu0TTBjFLm4XmwuxXAzfsZmkwCgYIKoZIzj0E
AwIERzBFAiBeNZewVOFI5aa7bPUXa05HDgz5yevQ9aPclDX6U+koTAIhAMbyysil
7I/UWLzhwM+9iusn3JXy71akUTcrqi2MNPaO
-----END SIGNED MESSAGE-----
`
	commitSHA = "040b9af339e69d18848b7bbe05cb27ee42bb0161"
)

func TestObjectHash(t *testing.T) {
	for _, tc := range []struct {
		name string
		body string
		sig  string
		sha  string
	}{
		{
			name: "tag",
			body: tagBody,
			sig:  tagSig,
			sha:  tagSHA,
		},
		{
			name: "commit",
			body: commitBody,
			sig:  commitSig,
			sha:  commitSHA,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got, err := ObjectHash([]byte(tc.body), []byte(tc.sig))
			if err != nil {
				t.Fatal(err)
			}
			if got != tc.sha {
				t.Errorf("want %s, got %s", tc.sha, got)
			}
		})
	}
}
