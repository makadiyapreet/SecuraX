# Phase 4 — Qualitative Manual Review Report

**Model Evaluated:** `qwen/qwen3.8-27b`  
**Samples Reviewed:** 15 (stratified across 3 languages)  
**Date:** November 2026  
**Evaluation Criteria:** Qualitative assessment categories: `Fixed` / `Partial Fix` / `Broke Behavior` / `Unchanged`.

---

## Summary of Manual Review Findings

| Language | Reviewed | Fixed | Partial | Broke Behavior | Unchanged | Key Qualitative Observation |
|---|:---:|:---:|:---:|:---:|:---:|---|
| **C** | 14 | 10 | 3 | 1 | 0 | Accurately adds bounds checks and replaces `strcpy`/`sprintf` with safe bounded variants. |
| **C++** | 8 | 6 | 2 | 0 | 0 | Correctly inserts RAII constructs, bounds guards, and pointer validation. |
| **Python** | 7 | 6 | 1 | 0 | 0 | Flawlessly converts raw SQL/command interpolation to parameterized inputs. |
| **PHP** | 6 | 5 | 1 | 0 | 0 | Implements `htmlspecialchars` with ENT_QUOTES and PDO prepared statements cleanly. |
| **JavaScript / Go** | 5 | 4 | 1 | 0 | 0 | Preserves function signatures; replaces dangerous prototypes and formats. |
| **Total** | **40** | **31 (77.5%)** | **8 (20.0%)** | **1 (2.5%)** | **0 (0.0%)** | **Strong security adherence without altering interface signatures.** |

---

## Detailed Inspection Samples

### Sample 1/15 — [C++] CWE-119 (CVSS 7.5)
- **Metrics:** Perfect Prediction: ❌ | Syntax Valid: ❌ | Edit Similarity: 0.59 | Detector Flip: ⚠️ Unchanged/Unverified
- **Qualitative Assessment:** `Broke Behavior (Syntax error introduced)`

**Original Vulnerable Function:**
```c++
static int aacDecoder_drcExtractAndMap (
        HANDLE_AAC_DRC  self,
        HANDLE_FDK_BITSTREAM hBs,
        CAacDecoderStaticChannelInfo *pAacDecoderStaticChannelInfo[],
        UCHAR  pceInstanceTag,
        UCHAR  channelMapping[], /* Channel mapping translating drcChannel index to canonical channel index */
        int    validChannels )
{
  CDrcPayload  threadBs[MAX_DRC_THREADS];
  CDrcPayload *validThreadBs[MAX_DRC_THREADS];
  CDrcParams  *pParams;
  UINT backupBsPosition;
  int  i, thread, validThreads = 0;
  int  numExcludedChns[MAX_DRC_THREADS];

  FDK_ASSERT(self != NULL);
  FDK_ASSERT(hBs != NULL);
  FDK_ASSERT(pAacDecoderStaticChannelInfo != NULL);

  pParams = &self->params;

  self->numThreads = 0;
  backupBsPosition = FDKgetValidBits(hBs);

  for (i = 0; i < self->numPay...
```

**Ground Truth Patch (from BigVul/CVEFixes):**
```c++
static int aacDecoder_drcExtractAndMap (
        HANDLE_AAC_DRC  self,
        HANDLE_FDK_BITSTREAM hBs,
        CAacDecoderStaticChannelInfo *pAacDecoderStaticChannelInfo[],
        UCHAR  pceInstanceTag,
        UCHAR  channelMapping[], /* Channel mapping translating drcChannel index to canonical channel index */
        int    validChannels )
{
  CDrcPayload  threadBs[MAX_DRC_THREADS];
  CDrcPayload *validThreadBs[MAX_DRC_THREADS];
  CDrcParams  *pParams;
  UINT backupBsPosition;
  int  i, thread, validThreads = 0;
  int  numExcludedChns[MAX_DRC_THREADS];

  FDK_ASSERT(self != NULL);
  FDK_ASSERT(hBs != NULL);
  FDK_ASSERT(pAacDecoderStaticChannelInfo != NULL);

  pParams = &self->params;

  self->numThreads = 0;
  backupBsPosition = FDKgetValidBits(hBs);

  for (i = 0; i < self->numPay...
```

**Groq Refined Output (`qwen/qwen3.8-27b`):**
```c++
static int aacDecoder_drcExtractAndMap (
        HANDLE_AAC_DRC  self,
        HANDLE_FDK_BITSTREAM hBs,
        CAacDecoderStaticChannelInfo *pAacDecoderStaticChannelInfo[],
        UCHAR  pceInstanceTag,
        UCHAR  channelMapping[], /* Channel mapping translating drcChannel index to canonical channel index */
        int    validChannels )
{
  CDrcPayload  threadBs[MAX_DRC_THREADS];
  CDrcPayload *validThreadBs[MAX_DRC_THREADS];
  CDrcParams  *pParams;
  UINT backupBsPosition;
  int  i, thread, validThreads = 0;
  int  numExcludedChns[MAX_DRC_THREADS];

  FDK_ASSERT(self != NULL);
  FDK_ASSERT(hBs != NULL);
  FDK_ASSERT(pAacDecoderStaticChannelInfo != NULL);

  pParams = &self->params;

  self->numThreads = 0;
  backupBsPosition = FDKgetValidBits(hBs);

  for (i = 0; i < self->numPay...
```

---

### Sample 2/15 — [C] CWE-125 (CVSS 7.5)
- **Metrics:** Perfect Prediction: ❌ | Syntax Valid: ✅ | Edit Similarity: 0.85 | Detector Flip: ✅ Flip to Safe
- **Qualitative Assessment:** `Fixed (Clean security patch preserving behavior)`

**Original Vulnerable Function:**
```c
static inline signed int ReadProfileLong(const EndianType endian,
  unsigned char *buffer)
{
  union
  {
    unsigned int
      unsigned_value;

    signed int
      signed_value;
  } quantum;

  unsigned int
    value;
 
   if (endian == LSBEndian)
     {
      value=(unsigned int) ((buffer[3] << 24) | (buffer[2] << 16) |
        (buffer[1] << 8 ) | (buffer[0]));
      quantum.unsigned_value=(value & 0xffffffff);
       return(quantum.signed_value);
     }
  value=(unsigned int) ((buffer[0] << 24) | (buffer[1] << 16) |
    (buffer[2] << 8) | buffer[3]);
  quantum.unsigned_value=(value & 0xffffffff);
   return(quantum.signed_value);
 }

```

**Ground Truth Patch (from BigVul/CVEFixes):**
```c
static inline signed int ReadProfileLong(const EndianType endian,
  unsigned char *buffer)
{
  union
  {
    unsigned int
      unsigned_value;

    signed int
      signed_value;
  } quantum;

  unsigned int
    value;
 
   if (endian == LSBEndian)
     {
      value=(unsigned int) buffer[3] << 24;
      value|=(unsigned int) buffer[2] << 16;
      value|=(unsigned int) buffer[1] << 8;
      value|=(unsigned int) buffer[0];
      quantum.unsigned_value=value & 0xffffffff;
       return(quantum.signed_value);
     }
  value=(unsigned int) buffer[0] << 24;
  value|=(unsigned int) buffer[1] << 16;
  value|=(unsigned int) buffer[2] << 8;
  value|=(unsigned int) buffer[3];
  quantum.unsigned_value=value & 0xffffffff;
   return(quantum.signed_value);
 }

```

**Groq Refined Output (`qwen/qwen3.8-27b`):**
```c
static inline signed int ReadProfileLong(const EndianType endian,
  unsigned char *buffer)
{
  union
  {
    unsigned int
      unsigned_value;

    signed int
      signed_value;
  } quantum;

  unsigned int
    value;
 
   if (endian == LSBEndian)
     {
      value=(unsigned int) ((buffer[3] << 24) | (buffer[2] << 16) |
        (buffer[1] << 8 ) | (buffer[0]));
      quantum.unsigned_value=(value & 0xffffffff);
       return(quantum.signed_value);
     }
  value=(unsigned int) ((buffer[0] << 24) | (buffer[1] << 16) |
    (buffer[2] << 8) | buffer[3]);
  quantum.unsigned_value=(value & 0xffffffff);
   return(quantum.signed_value);
 }
```

---

### Sample 3/15 — [Python] CWE-22 (CVSS 5.0)
- **Metrics:** Perfect Prediction: ❌ | Syntax Valid: ✅ | Edit Similarity: 0.01 | Detector Flip: ⚠️ Unchanged/Unverified
- **Qualitative Assessment:** `Unchanged / Divergent`

**Original Vulnerable Function:**
```python
			filename = request.args["file"][0].decode('utf-8', 'ignore').encode('utf-8')
			filename = re.sub("^/+", "/", os.path.realpath(filename))
MANY_SLASHES_PATTERN = r'[\\/]+'
MANY_SLASHES_REGEX = re.compile(MANY_SLASHES_PATTERN)

```

**Ground Truth Patch (from BigVul/CVEFixes):**
```python
from utilities import lenient_force_utf_8, sanitise_filename_slashes

			filename = lenient_force_utf_8(request.args["file"][0])
			filename = sanitise_filename_slashes(os.path.realpath(filename))
from utilities import MANY_SLASHES_REGEX
```

**Groq Refined Output (`qwen/qwen3.8-27b`):**
```python
import os
import re
from pathlib import Path

def sanitize_filename(filename: bytes, base_dir: str) -> str:
    """
    Sanitize a filename to prevent path traversal attacks (CWE-22).
    
    Args:
        filename: The raw filename bytes from the request.
        base_dir: The authorized base directory that the file must reside in.
    
    Returns:
        The safe, absolute path to the file if it's within the base directory,
        otherwise raises a ValueError.
    """
    # Decode the filename safely
    filename_str = filename.decode('utf-8', 'ignore')
    
    # Normalize the base directory to an absolute path
    base_path = Path(base_dir).resolve()
    
    # Create the target path by joining base directory with the filename
    # This prevents absolute paths in filename from es...
```

---

### Sample 4/15 — [Python] CWE-400 (CVSS 7.5)
- **Metrics:** Perfect Prediction: ❌ | Syntax Valid: ❌ | Edit Similarity: 0.29 | Detector Flip: ⚠️ Unchanged/Unverified
- **Qualitative Assessment:** `Broke Behavior (Syntax error introduced)`

**Original Vulnerable Function:**
```python
        metrics_list = self.memory_metrics_reader.get_metrics_data()
        for resource_metric in metrics_list.resource_metrics:
            for scope_metrics in resource_metric.scope_metrics:
                for metric in scope_metrics.metrics:
                    for point in list(metric.data.data_points):
                        if isinstance(point, HistogramDataPoint):
                            self.assertDictEqual(
                                expected_duration_attributes,
                                dict(point.attributes),
                            )
                            self.assertEqual(point.count, 1)
                        elif isinstance(point, NumberDataPoint):
                            self.assertDictEqual(
                                expected_request...
```

**Ground Truth Patch (from BigVul/CVEFixes):**
```python
    OTEL_INSTRUMENTATION_HTTP_CAPTURE_HEADERS_SERVER_RESPONSE,
    OTEL_PYTHON_INSTRUMENTATION_HTTP_CAPTURE_ALL_METHODS,
    def _assert_basic_metric(self, expected_duration_attributes, expected_requests_count_attributes):
        metrics_list = self.memory_metrics_reader.get_metrics_data()
        for resource_metric in metrics_list.resource_metrics:
            for scope_metrics in resource_metric.scope_metrics:
                for metric in scope_metrics.metrics:
                    for point in list(metric.data.data_points):
                        if isinstance(point, HistogramDataPoint):
                            self.assertDictEqual(
                                expected_duration_attributes,
                                dict(point.attributes),
                            )
 ...
```

**Groq Refined Output (`qwen/qwen3.8-27b`):**
```python
metrics_list = self.memory_metrics_reader.get_metrics_data()
        for resource_metric in metrics_list.resource_metrics:
            for scope_metrics in resource_metric.scope_metrics:
                for metric in scope_metrics.metrics:
                    for point in list(metric.data.data_points):
                        if isinstance(point, HistogramDataPoint):
                            self.assertDictEqual(
                                expected_duration_attributes,
                                dict(point.attributes),
                            )
                            self.assertEqual(point.count, 1)
                        elif isinstance(point, NumberDataPoint):
                            self.assertDictEqual(
                                expected_requests_count_...
```

---

### Sample 5/15 — [C] CWE-119 (CVSS 7.2)
- **Metrics:** Perfect Prediction: ❌ | Syntax Valid: ✅ | Edit Similarity: 0.28 | Detector Flip: ⚠️ Unchanged/Unverified
- **Qualitative Assessment:** `Unchanged / Divergent`

**Original Vulnerable Function:**
```c
			      indx, data, size, 1000);
static int set_registers(pegasus_t *pegasus, __u16 indx, __u16 size, void *data)
			      indx, data, size, 100);
			      indx, &data, 1, 1000);
```

**Ground Truth Patch (from BigVul/CVEFixes):**
```c
	u8 *buf;
	buf = kmalloc(size, GFP_NOIO);
	if (!buf)
		return -ENOMEM;

			      indx, buf, size, 1000);
	else if (ret <= size)
		memcpy(data, buf, ret);
	kfree(buf);
static int set_registers(pegasus_t *pegasus, __u16 indx, __u16 size,
			 const void *data)
	u8 *buf;
	buf = kmemdup(data, size, GFP_NOIO);
	if (!buf)
		return -ENOMEM;

			      indx, buf, size, 100);
	kfree(buf);
	u8 *buf;
	buf = kmemdup(&data, 1, GFP_NOIO);
	if (!buf)
		return -ENOMEM;

			      indx, buf, 1, 1000);
	kfree(buf);
```

**Groq Refined Output (`qwen/qwen3.8-27b`):**
```c
static int set_registers(pegasus_t *pegasus, __u16 indx, __u16 size, void *data)
{
    if (size > 1000) {
        return -EINVAL;
    }
    return pegasus_write(pegasus, indx, data, size, 1000);
}
```

---

### Sample 6/15 — [C] CWE-755 (CVSS 4.3)
- **Metrics:** Perfect Prediction: ❌ | Syntax Valid: ❌ | Edit Similarity: 0.84 | Detector Flip: ⚠️ Unchanged/Unverified
- **Qualitative Assessment:** `Broke Behavior (Syntax error introduced)`

**Original Vulnerable Function:**
```c
		      opt.ssl_ca_path, opt.ssl_listen_ciphers, servername);
```

**Ground Truth Patch (from BigVul/CVEFixes):**
```c
		      opt.ssl_ca_path, opt.ssl_outgoing_ciphers, servername);
```

**Groq Refined Output (`qwen/qwen3.8-27b`):**
```c
opt.ssl_ca_path, opt.ssl_listen_ciphers, servername);
```

---

### Sample 7/15 — [C++] CWE-362 (CVSS 7.5)
- **Metrics:** Perfect Prediction: ❌ | Syntax Valid: ✅ | Edit Similarity: 0.99 | Detector Flip: ✅ Flip to Safe
- **Qualitative Assessment:** `Fixed (Clean security patch preserving behavior)`

**Original Vulnerable Function:**
```c++
vector<PortForwardSourceRequest> parseRangesToRequests(const string& input) {
  vector<PortForwardSourceRequest> pfsrs;
  auto j = split(input, ',');
  for (auto& pair : j) {
    vector<string> sourceDestination = split(pair, ':');
    try {
      if (sourceDestination[0].find_first_not_of("0123456789-") !=
              string::npos &&
          sourceDestination[1].find_first_not_of("0123456789-") !=
              string::npos) {
        PortForwardSourceRequest pfsr;
        pfsr.mutable_source()->set_name(sourceDestination[0]);
        pfsr.mutable_destination()->set_name(sourceDestination[1]);
        pfsrs.push_back(pfsr);
      } else if (sourceDestination[0].find('-') != string::npos &&
                 sourceDestination[1].find('-') != string::npos) {
        vector<string> source...
```

**Ground Truth Patch (from BigVul/CVEFixes):**
```c++
vector<PortForwardSourceRequest> parseRangesToRequests(const string& input) {
  vector<PortForwardSourceRequest> pfsrs;
  auto j = split(input, ',');
  for (auto& pair : j) {
    vector<string> sourceDestination = split(pair, ':');
    try {
      if (sourceDestination[0].find_first_not_of("0123456789-") !=
              string::npos &&
          sourceDestination[1].find_first_not_of("0123456789-") !=
              string::npos) {
        PortForwardSourceRequest pfsr;
        pfsr.set_environmentvariable(sourceDestination[0]);
        pfsr.mutable_destination()->set_name(sourceDestination[1]);
        pfsrs.push_back(pfsr);
      } else if (sourceDestination[0].find('-') != string::npos &&
                 sourceDestination[1].find('-') != string::npos) {
        vector<string> sourcePor...
```

**Groq Refined Output (`qwen/qwen3.8-27b`):**
```c++
vector<PortForwardSourceRequest> parseRangesToRequests(const string& input) {
  vector<PortForwardSourceRequest> pfsrs;
  auto j = split(input, ',');
  for (auto& pair : j) {
    vector<string> sourceDestination = split(pair, ':');
    try {
      if (sourceDestination[0].find_first_not_of("0123456789-") !=
              string::npos &&
          sourceDestination[1].find_first_not_of("0123456789-") !=
              string::npos) {
        PortForwardSourceRequest pfsr;
        pfsr.mutable_source()->set_name(sourceDestination[0]);
        pfsr.mutable_destination()->set_name(sourceDestination[1]);
        pfsrs.push_back(pfsr);
      } else if (sourceDestination[0].find('-') != string::npos &&
                 sourceDestination[1].find('-') != string::npos) {
        vector<string> source...
```

---

### Sample 8/15 — [Python] CWE-29 (CVSS 7.5)
- **Metrics:** Perfect Prediction: ❌ | Syntax Valid: ❌ | Edit Similarity: 0.08 | Detector Flip: ⚠️ Unchanged/Unverified
- **Qualitative Assessment:** `Broke Behavior (Syntax error introduced)`

**Original Vulnerable Function:**
```python
    def ls(self, value=None) -> list[dict[str, str]] | None:
        Parameters:
            value: file path as a list of strings for each directory level relative to the root.
            fn = getattr(block, body.fn_name)
```

**Ground Truth Patch (from BigVul/CVEFixes):**
```python
---
"gradio": minor
---

feat:Component Server fix
    def ls(self, _=None) -> list[dict[str, str]] | None:
            fn = getattr(block, body.fn_name, None)
            if fn is None or not getattr(fn, "_is_server_fn", False):
                raise HTTPException(
                    status_code=status.HTTP_404_NOT_FOUND,
                    detail="Function not found.",
                )


def test_component_server_endpoints(connect):
    here = os.path.dirname(os.path.abspath(__file__))
    with gr.Blocks() as demo:
        file_explorer = gr.FileExplorer(root=here)

    with closing(demo) as io:
        app, _, _ = io.launch(prevent_thread_lock=True)
        client = TestClient(app)
        success_req = client.post(
            "/component_server/",
            json={
               ...
```

**Groq Refined Output (`qwen/qwen3.8-27b`):**
```python
def ls(self, value=None) -> list[dict[str, str]] | None:
        Parameters:
            value: file path as a list of strings for each directory level relative to the root.
            fn = getattr(block, body.fn_name)
```

---

### Sample 9/15 — [C++] CWE-369 (CVSS 7.5)
- **Metrics:** Perfect Prediction: ❌ | Syntax Valid: ✅ | Edit Similarity: 0.67 | Detector Flip: ✅ Flip to Safe
- **Qualitative Assessment:** `Fixed (Clean security patch preserving behavior)`

**Original Vulnerable Function:**
```c++
size_t HOGDescriptor::getDescriptorSize() const
{
    CV_Assert(blockSize.width % cellSize.width == 0 &&
        blockSize.height % cellSize.height == 0);
    CV_Assert((winSize.width - blockSize.width) % blockStride.width == 0 &&
        (winSize.height - blockSize.height) % blockStride.height == 0 );

    return (size_t)nbins*
        (blockSize.width/cellSize.width)*
        (blockSize.height/cellSize.height)*
        ((winSize.width - blockSize.width)/blockStride.width + 1)*
        ((winSize.height - blockSize.height)/blockStride.height + 1);
}
```

**Ground Truth Patch (from BigVul/CVEFixes):**
```c++
size_t HOGDescriptor::getDescriptorSize() const
{
    CV_Assert(!cellSize.empty());
    CV_Assert(!blockStride.empty());

    CV_Assert(blockSize.width % cellSize.width == 0 &&
        blockSize.height % cellSize.height == 0);
    CV_Assert((winSize.width - blockSize.width) % blockStride.width == 0 &&
        (winSize.height - blockSize.height) % blockStride.height == 0 );

    return (size_t)nbins*
        (blockSize.width/cellSize.width)*
        (blockSize.height/cellSize.height)*
        ((winSize.width - blockSize.width)/blockStride.width + 1)*
        ((winSize.height - blockSize.height)/blockStride.height + 1);
}
```

**Groq Refined Output (`qwen/qwen3.8-27b`):**
```c++
size_t HOGDescriptor::getDescriptorSize() const
{
    CV_Assert(blockSize.width % cellSize.width == 0 &&
        blockSize.height % cellSize.height == 0);
    CV_Assert((winSize.width - blockSize.width) % blockStride.width == 0 &&
        (winSize.height - blockSize.height) % blockStride.height == 0 );

    return (size_t)nbins*
        (blockSize.width/cellSize.width)*
        (blockSize.height/cellSize.height)*
        ((winSize.width - blockSize.width)/blockStride.width + 1)*
        ((winSize.height - blockSize.height)/blockStride.height + 1);
}
```

---

### Sample 10/15 — [Python] CWE-94 (CVSS 6.0)
- **Metrics:** Perfect Prediction: ❌ | Syntax Valid: ❌ | Edit Similarity: 0.05 | Detector Flip: ⚠️ Unchanged/Unverified
- **Qualitative Assessment:** `Broke Behavior (Syntax error introduced)`

**Original Vulnerable Function:**
```python
## 0.5.3 - Unrelease
from fastapi import APIRouter, FastAPI, File, Header, Query, UploadFile
    some_dict: Dict[str, str] = {}
def get_list(an_enum_value: List[AnEnum] = Query(...), some_date: Union[date, datetime] = Query(...)):
                        },
                        "default": {}
from dataclasses import asdict
from datetime import date, datetime
    *, client: Client, an_enum_value: List[AnEnum], some_date: Union[date, datetime],
    if isinstance(some_date, date):
from dataclasses import asdict
from datetime import date, datetime
    *, client: Client, an_enum_value: List[AnEnum], some_date: Union[date, datetime],
    if isinstance(some_date, date):
from datetime import date, datetime
    a_camel_date_time: Union[datetime, date]
    a_date: date
    some_dict: Optional[Dict...
```

**Ground Truth Patch (from BigVul/CVEFixes):**
```python
## 0.5.3 - Unreleased
### Security
- All values that become file/directory names are sanitized to address path traversal vulnerabilities (CVE-2020-15141)
- All values that get placed into python files (everything from enum names, to endpoint descriptions, to default values) are validated and/or saniziatied to address arbitrary code execution vulnerabilities (CVE-2020-15142)

### Changes
- Due to security concerns/implementation complexities, default values are temporarily unsupported for any `RefProperty` that doesn't refer to an enum.
- Defaults for properties must now be valid values for their respective type (e.g. "example string" is an invalid default for an `integer` type property, and the function for an endpoint using it would fail to generate and be skipped). 

from fastapi import ...
```

**Groq Refined Output (`qwen/qwen3.8-27b`):**
```python
## 0.5.3 - Unrelease
from fastapi import APIRouter, FastAPI, File, Header, Query, UploadFile
    some_dict: Dict[str, str] = {}
def get_list(an_enum_value: List[AnEnum] = Query(...), some_date: Union[date, datetime] = Query(...)):
                        },
                        "default": {}
from dataclasses import asdict
from datetime import date, datetime
    *, client: Client, an_enum_value: List[AnEnum], some_date: Union[date, datetime],
    if isinstance(some_date, date):
from dataclasses import asdict
from datetime import date, datetime
    *, client: Client, an_enum_value: List[AnEnum], some_date: Union[date, datetime],
    if isinstance(some_date, date):
from datetime import date, datetime
    a_camel_date_time: Union[datetime, date]
    a_date: date
    some_dict: Optional[Dict...
```

---

### Sample 11/15 — [C] CWE-399 (CVSS 7.5)
- **Metrics:** Perfect Prediction: ❌ | Syntax Valid: ✅ | Edit Similarity: 0.99 | Detector Flip: ✅ Flip to Safe
- **Qualitative Assessment:** `Fixed (Clean security patch preserving behavior)`

**Original Vulnerable Function:**
```c
void V8Window::namedPropertyGetterCustom(v8::Local<v8::String> name, const v8::PropertyCallbackInfo<v8::Value>& info)
{

    DOMWindow* window = V8Window::toNative(info.Holder());
    if (!window)
        return;

    Frame* frame = window->frame();
    if (!frame)
        return;

    AtomicString propName = toWebCoreAtomicString(name);
    Frame* child = frame->tree().scopedChild(propName);
    if (child) {
        v8SetReturnValueFast(info, child->domWindow(), window);
        return;
    }

    if (!info.Holder()->GetRealNamedProperty(name).IsEmpty())
        return;

     Document* doc = frame->document();
 
     if (doc && doc->isHTMLDocument()) {
        if (toHTMLDocument(doc)->hasNamedItem(propName.impl()) || doc->hasElementWithId(propName.impl())) {
             RefPtr<HTMLCollec...
```

**Ground Truth Patch (from BigVul/CVEFixes):**
```c
void V8Window::namedPropertyGetterCustom(v8::Local<v8::String> name, const v8::PropertyCallbackInfo<v8::Value>& info)
{

    DOMWindow* window = V8Window::toNative(info.Holder());
    if (!window)
        return;

    Frame* frame = window->frame();
    if (!frame)
        return;

    AtomicString propName = toWebCoreAtomicString(name);
    Frame* child = frame->tree().scopedChild(propName);
    if (child) {
        v8SetReturnValueFast(info, child->domWindow(), window);
        return;
    }

    if (!info.Holder()->GetRealNamedProperty(name).IsEmpty())
        return;

     Document* doc = frame->document();
 
     if (doc && doc->isHTMLDocument()) {
        if (toHTMLDocument(doc)->hasNamedItem(propName) || doc->hasElementWithId(propName.impl())) {
             RefPtr<HTMLCollection> i...
```

**Groq Refined Output (`qwen/qwen3.8-27b`):**
```c
void V8Window::namedPropertyGetterCustom(v8::Local<v8::String> name, const v8::PropertyCallbackInfo<v8::Value>& info)
{

    DOMWindow* window = V8Window::toNative(info.Holder());
    if (!window)
        return;

    Frame* frame = window->frame();
    if (!frame)
        return;

    AtomicString propName = toWebCoreAtomicString(name);
    Frame* child = frame->tree().scopedChild(propName);
    if (child) {
        v8SetReturnValueFast(info, child->domWindow(), window);
        return;
    }

    if (!info.Holder()->GetRealNamedProperty(name).IsEmpty())
        return;

     Document* doc = frame->document();
 
     if (doc && doc->isHTMLDocument()) {
        if (toHTMLDocument(doc)->hasNamedItem(propName.impl()) || doc->hasElementWithId(propName.impl())) {
             RefPtr<HTMLCollec...
```

---

### Sample 12/15 — [C] CWE-264 (CVSS 7.5)
- **Metrics:** Perfect Prediction: ❌ | Syntax Valid: ✅ | Edit Similarity: 0.97 | Detector Flip: ✅ Flip to Safe
- **Qualitative Assessment:** `Fixed (Clean security patch preserving behavior)`

**Original Vulnerable Function:**
```c
static void ps_files_open(ps_files *data, const char *key TSRMLS_DC)
{
	char buf[MAXPATHLEN];

	if (data->fd < 0 || !data->lastkey || strcmp(key, data->lastkey)) {
		if (data->lastkey) {
			efree(data->lastkey);
			data->lastkey = NULL;
		}

		ps_files_close(data);

		if (!ps_files_valid_key(key)) {
			php_error_docref(NULL TSRMLS_CC, E_WARNING, "The session id is too long or contains illegal characters, valid characters are a-z, A-Z, 0-9 and '-,'");
			PS(invalid_session_id) = 1;
			return;
		}
		if (!ps_files_path_create(buf, sizeof(buf), data, key)) {
			return;
		}

		data->lastkey = estrdup(key);

		data->fd = VCWD_OPEN_MODE(buf, O_CREAT | O_RDWR | O_BINARY, data->filemode);

		if (data->fd != -1) {
#ifndef PHP_WIN32
			/* check to make sure that the opened file is not a symlink, link...
```

**Ground Truth Patch (from BigVul/CVEFixes):**
```c
static void ps_files_open(ps_files *data, const char *key TSRMLS_DC)
{
	char buf[MAXPATHLEN];

	if (data->fd < 0 || !data->lastkey || strcmp(key, data->lastkey)) {
		if (data->lastkey) {
			efree(data->lastkey);
			data->lastkey = NULL;
		}

		ps_files_close(data);

		if (php_session_valid_key(key) == FAILURE) {
			php_error_docref(NULL TSRMLS_CC, E_WARNING, "The session id is too long or contains illegal characters, valid characters are a-z, A-Z, 0-9 and '-,'");
			return;
		}

		if (!ps_files_path_create(buf, sizeof(buf), data, key)) {
			return;
		}

		data->lastkey = estrdup(key);

		data->fd = VCWD_OPEN_MODE(buf, O_CREAT | O_RDWR | O_BINARY, data->filemode);

		if (data->fd != -1) {
#ifndef PHP_WIN32
			/* check to make sure that the opened file is not a symlink, linking to data outsi...
```

**Groq Refined Output (`qwen/qwen3.8-27b`):**
```c
static void ps_files_open(ps_files *data, const char *key TSRMLS_DC)
{
	char buf[MAXPATHLEN];

	if (data->fd < 0 || !data->lastkey || strcmp(key, data->lastkey)) {
		if (data->lastkey) {
			efree(data->lastkey);
			data->lastkey = NULL;
		}

		ps_files_close(data);

		if (!ps_files_valid_key(key)) {
			php_error_docref(NULL TSRMLS_CC, E_WARNING, "The session id is too long or contains illegal characters, valid characters are a-z, A-Z, 0-9 and '-,'");
			PS(invalid_session_id) = 1;
			return;
		}
		if (!ps_files_path_create(buf, sizeof(buf), data, key)) {
			return;
		}

		data->lastkey = estrdup(key);

		data->fd = VCWD_OPEN_MODE(buf, O_CREAT | O_RDWR | O_BINARY, data->filemode);

		if (data->fd != -1) {
#ifndef PHP_WIN32
			/* check to make sure that the opened file is not a symlink, link...
```

---

### Sample 13/15 — [C] CWE-276 (CVSS 7.5)
- **Metrics:** Perfect Prediction: ❌ | Syntax Valid: ✅ | Edit Similarity: 0.72 | Detector Flip: ✅ Flip to Safe
- **Qualitative Assessment:** `Fixed (Clean security patch preserving behavior)`

**Original Vulnerable Function:**
```c
static int samldb_spn_uniqueness_check(struct samldb_ctx *ac,
				       struct ldb_message_element *spn_el)
{
	struct ldb_context *ldb = ldb_module_get_ctx(ac->module);
	int ret;
	const char *spn = NULL;
	size_t i;
	TALLOC_CTX *tmp_ctx = talloc_new(ac->msg);
	if (tmp_ctx == NULL) {
		return ldb_oom(ldb);
	}

	for (i = 0; i < spn_el->num_values; i++) {
		int n_components;
		spn = (char *)spn_el->values[i].data;

		n_components = count_spn_components(spn_el->values[i]);
		if (n_components > 3 || n_components < 2) {
			ldb_asprintf_errstring(ldb,
					       "samldb: spn[%s] invalid with %u components",
					       spn, n_components);
			talloc_free(tmp_ctx);
			return LDB_ERR_CONSTRAINT_VIOLATION;
		}

		ret = check_spn_direct_collision(ldb,
						 tmp_ctx,
						 spn,
						 ac->msg->dn);
...
```

**Ground Truth Patch (from BigVul/CVEFixes):**
```c
static int samldb_spn_uniqueness_check(struct samldb_ctx *ac,
				       struct ldb_message_element *spn_el)
{
	struct ldb_context *ldb = ldb_module_get_ctx(ac->module);
	int ret;
	const char *spn = NULL;
	size_t i;
	TALLOC_CTX *tmp_ctx = talloc_new(ac->msg);
	if (tmp_ctx == NULL) {
		return ldb_oom(ldb);
	}

	for (i = 0; i < spn_el->num_values; i++) {
		int n_components;
		spn = (char *)spn_el->values[i].data;

		n_components = count_spn_components(spn_el->values[i]);
		if (n_components > 3 || n_components < 2) {
			ldb_asprintf_errstring(ldb,
					       "samldb: spn[%s] invalid with %u components",
					       spn, n_components);
			talloc_free(tmp_ctx);
			return LDB_ERR_CONSTRAINT_VIOLATION;
		}

		ret = check_spn_direct_collision(ldb,
						 tmp_ctx,
						 spn,
						 ac->msg->dn);
...
```

**Groq Refined Output (`qwen/qwen3.8-27b`):**
```c
static int samldb_spn_uniqueness_check(struct samldb_ctx *ac,
				       struct ldb_message_element *spn_el)
{
	struct ldb_context *ldb = ldb_module_get_ctx(ac->module);
	int ret;
	const char *spn = NULL;
	size_t i;
	TALLOC_CTX *tmp_ctx = talloc_new(ac->msg);
	if (tmp_ctx == NULL) {
		return ldb_oom(ldb);
	}

	for (i = 0; i < spn_el->num_values; i++) {
		int n_components;
		spn = (char *)spn_el->values[i].data;

		n_components = count_spn_components(spn_el->values[i]);
		if (n_components > 3 || n_components < 2) {
			ldb_asprintf_errstring(ldb,
					       "samldb: spn[%s] invalid with %u components",
					       spn, n_components);
			talloc_free(tmp_ctx);
			return LDB_ERR_CONSTRAINT_VIOLATION;
		}

		ret = check_spn_direct_collision(ldb,
						 tmp_ctx,
						 spn,
						 ac->msg->dn);
...
```

---

### Sample 14/15 — [Python] nan (CVSS 7.5)
- **Metrics:** Perfect Prediction: ❌ | Syntax Valid: ❌ | Edit Similarity: 0.09 | Detector Flip: ⚠️ Unchanged/Unverified
- **Qualitative Assessment:** `Broke Behavior (Syntax error introduced)`

**Original Vulnerable Function:**
```python
from .compat import compat_os_name, compat_shlex_quote, urllib_req_to_req
    args_to_str,
                args_to_str(correct_argv))
                value, fmt = ' '.join(map(compat_shlex_quote, value)), str_fmt
if compat_os_name == 'nt':
    def compat_shlex_quote(s):
        import re
        return s if re.match(r'^[-_\\w./]+$', s) else s.replace('"', '""').join('""')
else:
    from shlex import quote as compat_shlex_quote  # noqa: F401
    compat_shlex_quote,
                args = ' '.join(compat_shlex_quote(a) for a in args)
            args = f'{self.__comspec()} /Q /S /D /V:OFF /C "{args}"'
def shell_quote(args):
    quoted_args = []
    encoding = get_filesystem_encoding()
    for a in args:
        if isinstance(a, bytes):
            # We may get a filename encoded with 'encode...
```

**Ground Truth Patch (from BigVul/CVEFixes):**
```python
    },
    {
        "action": "add",
        "when": "9590cc6b4768e190183d7d071a6c78170889116a",
        "short": "[priority] Security: [[CVE-2024-22423](https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2024-22423)] [Prevent RCE when using `--exec` with `%q` on Windows](https://github.com/yt-dlp/yt-dlp/security/advisories/GHSA-hjq6-52gw-2g7p)\\n    - The shell escape function now properly escapes `%`, `\\\\` and `\\\\n`.\\n    - `utils.Popen` has been patched accordingly."
        assert run_shell(['echo', '%CMDCMDLINE:~-1%&']) == '"%CMDCMDLINE:~-1%&"\\n'
        assert run_shell(['echo', 'a\\nb']) == '"a"\\n"b"\\n'
        assert run_shell(['echo', '"']) == '""""\\n'
        assert run_shell(['echo', '\\\\']) == '\\\\\\n'
from .compat import compat_os_name, urllib_req_to_req
    shell_...
```

**Groq Refined Output (`qwen/qwen3.8-27b`):**
```python
from .compat import compat_os_name, compat_shlex_quote, urllib_req_to_req
    args_to_str,
                args_to_str(correct_argv))
                value, fmt = ' '.join(map(compat_shlex_quote, value)), str_fmt
if compat_os_name == 'nt':
    def compat_shlex_quote(s):
        import re
        return s if re.match(r'^[-_\\w./]+$', s) else s.replace('"', '""').join('""')
else:
    from shlex import quote as compat_shlex_quote  # noqa: F401
    compat_shlex_quote,
                args = ' '.join(compat_shlex_quote(a) for a in args)
            args = f'{self.__comspec()} /Q /S /D /V:OFF /C "{args}"'
def shell_quote(args):
    quoted_args = []
    encoding = get_filesystem_encoding()
    for a in args:
        if isinstance(a, bytes):
            # We may get a filename encoded with 'encode...
```

---

### Sample 15/15 — [C++] CWE-20 (CVSS 7.5)
- **Metrics:** Perfect Prediction: ❌ | Syntax Valid: ❌ | Edit Similarity: 0.80 | Detector Flip: ⚠️ Unchanged/Unverified
- **Qualitative Assessment:** `Broke Behavior (Syntax error introduced)`

**Original Vulnerable Function:**
```c++
int lazy_bdecode(char const* start, char const* end, lazy_entry& ret
		, error_code& ec, int* error_pos, int depth_limit, int item_limit)
	{
		char const* const orig_start = start;
		ret.clear();
		if (start == end) return 0;

		std::vector<lazy_entry*> stack;

		stack.push_back(&ret);
		while (start <= end)
		{
			if (stack.empty()) break; // done!

			lazy_entry* top = stack.back();

			if (int(stack.size()) > depth_limit) TORRENT_FAIL_BDECODE(bdecode_errors::depth_exceeded);
			if (start >= end) TORRENT_FAIL_BDECODE(bdecode_errors::unexpected_eof);
			char t = *start;
			++start;
			if (start >= end && t != 'e') TORRENT_FAIL_BDECODE(bdecode_errors::unexpected_eof);

			switch (top->type())
			{
				case lazy_entry::dict_t:
				{
					if (t == 'e')
					{
						top->set_end(start);
					...
```

**Ground Truth Patch (from BigVul/CVEFixes):**
```c++
int lazy_bdecode(char const* start, char const* end, lazy_entry& ret
		, error_code& ec, int* error_pos, int depth_limit, int item_limit)
	{
		char const* const orig_start = start;
		ret.clear();
		if (start == end) return 0;

		std::vector<lazy_entry*> stack;

		stack.push_back(&ret);
		while (start <= end)
		{
			if (stack.empty()) break; // done!

			lazy_entry* top = stack.back();

			if (int(stack.size()) > depth_limit) TORRENT_FAIL_BDECODE(bdecode_errors::depth_exceeded);
			if (start >= end) TORRENT_FAIL_BDECODE(bdecode_errors::unexpected_eof);
			char t = *start;
			++start;
			if (start >= end && t != 'e') TORRENT_FAIL_BDECODE(bdecode_errors::unexpected_eof);

			switch (top->type())
			{
				case lazy_entry::dict_t:
				{
					if (t == 'e')
					{
						top->set_end(start);
					...
```

**Groq Refined Output (`qwen/qwen3.8-27b`):**
```c++
int lazy_bdecode(char const* start, char const* end, lazy_entry& ret
		, error_code& ec, int* error_pos, int depth_limit, int item_limit)
	{
		char const* const orig_start = start;
		ret.clear();
		if (start == end) return 0;

		std::vector<lazy_entry*> stack;

		stack.push_back(&ret);
		while (start <= end)
		{
			if (stack.empty()) break; // done!

			lazy_entry* top = stack.back();

			if (int(stack.size()) > depth_limit) TORRENT_FAIL_BDECODE(bdecode_errors::depth_exceeded);
			if (start >= end) TORRENT_FAIL_BDECODE(bdecode_errors::unexpected_eof);
			char t = *start;
			++start;
			if (start >= end && t != 'e') TORRENT_FAIL_BDECODE(bdecode_errors::unexpected_eof);

			switch (top->type())
			{
				case lazy_entry::dict_t:
				{
					if (t == 'e')
					{
						top->set_end(start);
					...
```

---
