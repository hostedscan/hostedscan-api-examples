# Run Scans and Get Risks - bash

This example starts a new Scan, waits for the Scan to finish, and then gets the Risks found by the Scan.

## Requirements

This example requires jq (a lightweight and flexible command-line JSON processor) to be installed. See https://stedolan.github.io/jq/download/ for install instructions.

## How to Run the Example

Run the code with your HostedScan API key environment variable: `HOSTEDSCAN_API_KEY=<key> ./run_scan` or use our API test key `HOSTEDSCAN_API_KEY=test-data-key ./run_scan` (note: the API test key returns cached responses and does not run actual scans).

## Example Output

```
Started Scan with id: 61918df1ed4b650040af5b0a
Waiting for Scan to finish running...
Scan state: RUNNING. Sleeping 15 seconds...
Scan state: SUCCEEDED. Scan finished!

0 New Open Risks


1 Still Open Risks

MEDIUM	(is_accepted: false)	certificate has expired

0 Closed Risks
```

## Details of the API Call Flow

### 1. Start a New Scan

To start a new Scan, you call the [Create Scan](https://docs.hostedscan.com/api/scans/create-scan) endpoint. The response is a Scan object. The Scan object contains the id of the Scan.

```
{
  "data": {
    "id": "example-id",
    ...
  }
}
```

### 2. Wait for the Scan to Finish

When a Scan is first started, it will be in the QUEUED state. It then transitions to the RUNNING state and finally the SUCCEEDED state.

To check the current state of a Scan, you call the [Get Scans](https://docs.hostedscan.com/api/scans/get-scans) endpoint. The response is a Scan object. The Scan object contains the current state.

```
{
  "data": {
    "id": "example-id",
    "state": "RUNNING",
    ...
  }
}
```

To wait for the Scan to finish, you periodically poll to check the state. Alternatively, you can use [Webhooks](https://docs.hostedscan.com/webhooks/overview) and listen for the `scan.succeeded` event.

### 3. Get the Risks

Once the Scan is finished (in the SUCCEEDED state), the Scan object contains the ids for any discovered Risks. The Scan object also contains ids for any Result files. These files are the native reports from each vulnerability scanner (e.g. the OWASP ZAP JSON result, the OpenVAS XML result, etc...).

```
{
  "data": {
    "id": "example-id",
    "state": "SUCCEEDED",
    "risks": {
      "new_open": [
        {
          "risk_id": "risk-123",
        }
      ],
      "still_open": [
        {
          "risk_id": "risk-456",
        }
      ],
      "closed": [
        {
          "risk_id": "risk-789",
        }
      ]
    },
    "results": [
      {
        "result_id": "result-123",
        "content_type": "text/html",
      },
      {
        "result_id": "result-456",
        "content_type": "application/json",
      },
    ]
  }
}
```

The Risks are grouped into 3 categories: `new_open`, `still_open`, and `closed`. `new_open` are Risks that were detected for the first time in this Scan. `still_open` are Risks that were detected in previous Scans and still detected in this Scan. `closed` are Risks that were detected in previous Scans and not detected in this Scan.

To get the full information about each Risk, you call the [Get Risks(s)](https://docs.hostedscan.com/api/scans/get-risks) endpoint. The response is a Risk object, which contains the details such as the title, threat_level, and the is_accepted flag.

### 4. Download the PDF Scan Result file

The Scan object contains a list of result file formats and ids:

```
"results":[
  {
    "result_id":"627855c972c53e004090c163",
    "content_type":"application/json"
  },
  {
    "result_id":"627855c972c53e004090c162",
    "content_type":"text/html"
  },
  {
    "result_id":"627855c972c53e004090c164",
    "content_type":"application/pdf"
  }
]
```