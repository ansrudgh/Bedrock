# 4강 미션: FLIoT 코드 RAG 스타일/보안 리뷰

---

## 분석 개요

| 항목 | 내용 |
|------|------|
| 생성 일시 | 2026-05-22 01:13:02 |
| 저장소 | https://github.com/ansrudgh/FLIoT |
| 분석 파일 | `FLIoT\label_csv_sender.py` |
| 총 검사 라인 수 | 348줄 |
| 검사 방식 | Amazon Bedrock Knowledge Base RetrieveAndGenerate |
| 사용 모델 | global.anthropic.claude-sonnet-4-6 |
| 리전 | ap-southeast-2 |
| Knowledge Base ID | 3YKUZNB2SN |

---

## 1. 코드 스타일 검토 (PEP 8 기준)

### S-01 · 연산자 주변 공백 누락

| 항목 | 내용 |
|------|------|
| **라인** | 96, 134, 265 |
| **문제** | `i+1`, `file_index-1`, `num_clients+1` 등 산술 연산자 양쪽에 공백이 없음 |
| **근거** | PEP 8 — 이항 연산자 양쪽에는 단일 공백을 두어야 함 |
| **수정 방향** | `i + 1`, `file_index - 1`, `num_clients + 1` 으로 변경 |

---

### S-02 · 불필요한 공백 (콜론 앞)

| 항목 | 내용 |
|------|------|
| **라인** | 201 |
| **문제** | `else :` — `else` 키워드와 콜론 사이에 불필요한 공백이 존재 |
| **근거** | PEP 8 — 콜론, 세미콜론, 괄호 바로 앞에는 공백을 두지 않음 |
| **수정 방향** | `else:` 로 변경 |

---

### S-03 · 루프 내 반복 객체 생성

| 항목 | 내용 |
|------|------|
| **라인** | 53–57 |
| **문제** | `for col in available_features` 루프 안에서 매 반복마다 `MinMaxScaler()` 인스턴스를 새로 생성 |
| **근거** | 불필요한 객체 생성은 가독성을 낮추고 성능에도 영향을 줄 수 있음; 컬럼별 독립 스케일링이 의도라면 주석으로 명시 필요 |
| **수정 방향** | 의도가 컬럼별 독립 스케일링이라면 주석으로 명확히 표기하고, 전체 일괄 스케일링이 목적이라면 루프 밖으로 이동 |

```python
# 컬럼별 독립 스케일링이 의도인 경우 — 주석 명시
for col in available_features:
    df[col] = df[col].replace([np.inf, -np.inf], np.nan)
    df[col] = df[col].fillna(df[col].median())
    scaler = MinMaxScaler()  # 컬럼별 독립 스케일 적용
    df[col] = scaler.fit_transform(df[col].values.reshape(-1, 1))
```

---

### S-04 · 중복 주석

| 항목 | 내용 |
|------|------|
| **라인** | 163–164 |
| **문제** | 인라인 주석 `# 원래 라벨을 그대로 사용` 과 바로 위 줄의 주석이 동일한 내용을 반복 |
| **근거** | PEP 8 — 주석은 코드가 설명하지 못하는 이유(why)를 담아야 하며, 자명한 내용의 중복 주석은 지양 |
| **수정 방향** | 인라인 주석 또는 위 줄 주석 중 하나를 제거 |

---

### S-05 · `main()` 함수 길이 과다

| 항목 | 내용 |
|------|------|
| **라인** | 70–345 |
| **문제** | `main()` 함수가 275줄에 달하며, CSV 선택·전처리·라벨 필터링·소켓 전송 등 여러 책임을 단일 함수에서 처리 |
| **근거** | 단일 책임 원칙(SRP); 함수가 길어질수록 테스트·유지보수가 어려워짐 |
| **수정 방향** | `select_csv_file()`, `filter_labels()`, `send_data()` 등 역할별 함수로 분리 |

---

### S-06 · `headers` 변수 미사용

| 항목 | 내용 |
|------|------|
| **라인** | 300 |
| **문제** | `headers = next(reader)` 로 헤더를 읽어 변수에 저장하지만 이후 어디서도 사용되지 않음 |
| **근거** | PEP 8 / 가독성 — 사용하지 않는 변수는 `_` 로 표기하거나 제거 권장 |
| **수정 방향** | `_ = next(reader)` 또는 `next(reader)` 로 변경 |

---

### S-07 · 오타 (논리적 버그 가능성)

| 항목 | 내용 |
|------|------|
| **라인** | 172 |
| **문제** | `"nomaly"` — `"normal"` 의 오타로 추정됨 |
| **근거** | 문자열 오타는 런타임 오류 없이 잘못된 라벨을 생성하여 하위 처리 로직에 영향을 줄 수 있음 |
| **수정 방향** | `"normal"` 로 수정 |

```python
df["Label"] = df["Label"].apply(
    lambda x: "normal" if str(x).strip().upper() == "BENIGN" else "anomaly"
)
```

---

## 2. 보안 취약점 검토 (OWASP 기준)

### V-01 · 환경 변수 미검증으로 인한 예외 처리 불완전

| 항목 | 내용 |
|------|------|
| **라인** | 252–256 |
| **심각도** | 🟡 중간 (Medium) |
| **OWASP Top 10** | A05:2021 – Security Misconfiguration |
| **문제** | `os.environ.get("CLIENT")` 의 반환값이 `None` 일 때 `int(None)` 을 시도하면 `TypeError` 가 발생하지만, `except` 블록이 `ValueError` 만 잡고 있어 `TypeError` 는 처리되지 않음. `num_clients = 1` 로 폴백되지 않고 예외가 전파될 수 있음 |
| **근거** | 환경 변수는 항상 존재를 보장할 수 없으므로 기본값 처리와 예외 유형을 명확히 해야 함 |
| **수정 방향** | `os.environ.get("CLIENT", "1")` 로 기본값을 지정하거나, `except (ValueError, TypeError)` 로 예외 범위를 확장 |

```python
client_val = os.environ.get("CLIENT", "1")
try:
    num_clients = int(client_val)
except (ValueError, TypeError):
    num_clients = 1
```

---

### V-02 · 사용자 입력 IP 주소 미검증

| 항목 | 내용 |
|------|------|
| **라인** | 279–288 |
| **심각도** | 🟠 높음 (High) |
| **OWASP Top 10** | A03:2021 – Injection / A01:2021 – Broken Access Control |
| **문제** | 사용자로부터 직접 입력받은 IP 주소(`ip`)와 포트 번호(`port`)에 대해 형식 검증이 전혀 없음. 임의의 내부 네트워크 주소나 특수 주소(예: `0.0.0.0`, `127.0.0.1`, 브로드캐스트 주소 등)로 소켓 연결이 시도될 수 있음 |
| **근거** | 검증되지 않은 네트워크 대상으로의 연결은 SSRF(Server-Side Request Forgery) 유사 위험을 내포하며, 의도치 않은 내부망 접근으로 이어질 수 있음 |
| **수정 방향** | `ipaddress` 모듈로 IP 형식 검증, 포트 범위(1–65535) 확인, 허용 IP 대역 화이트리스트 적용 |

```python
import ipaddress

def validate_ip_port(ip: str, port: int) -> bool:
    try:
        ipaddress.ip_address(ip)
    except ValueError:
        return False
    return 1 <= port <= 65535
```

---

### V-03 · 소켓 연결 타임아웃 미설정

| 항목 | 내용 |
|------|------|
| **라인** | 292–295 |
| **심각도** | 🟡 중간 (Medium) |
| **OWASP Top 10** | A05:2021 – Security Misconfiguration |
| **문제** | `socket.socket()` 생성 후 `sock.connect()` 호출 전에 타임아웃이 설정되어 있지 않음. 응답하지 않는 호스트에 연결 시도 시 프로세스가 무기한 블로킹될 수 있음 |
| **근거** | 타임아웃 없는 소켓은 DoS 상태(자원 고갈)를 유발할 수 있으며, 운영 환경에서 안정성을 저해함 |
| **수정 방향** | `sock.settimeout(10)` 등 적절한 타임아웃 값을 연결 전에 설정 |

```python
sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
sock.settimeout(10)  # 10초 타임아웃 설정
```

---

### V-04 · 출력 파일명에 사용자 유래 데이터 포함

| 항목 | 내용 |
|------|------|
| **라인** | 234–235 |
| **심각도** | 🟡 중간 (Medium) |
| **OWASP Top 10** | A03:2021 – Injection |
| **문제** | `joined_labels`는 CSV 파일 내 `Label` 컬럼 값에서 직접 추출되며, 이를 파일명(`output_filename`)에 그대로 삽입함. 라벨 값에 경로 구분자(`/`, `\`, `..`)나 특수문자가 포함될 경우 경로 순회(Path Traversal) 위험이 있음 |
| **근거** | 외부 데이터에서 유래한 값을 파일 시스템 경로에 사용할 때는 반드시 정제가 필요함 |
| **수정 방향** | `re.sub` 또는 `pathlib`을 활용해 파일명에 허용되지 않는 문자를 제거하거나 치환 |

```python
import re
safe_label = re.sub(r'[^\w\-]', '_', joined_labels)
output_filename = f"selected_labels_{safe_label}.csv"
```

---

### V-05 · `.env` 파일 경로 하드코딩

| 항목 | 내용 |
|------|------|
| **라인** | 12 |
| **심각도** | 🟢 낮음 (Low) |
| **OWASP Top 10** | A05:2021 – Security Misconfiguration |
| **문제** | `load_dotenv('.env')` 로 `.env` 파일 경로가 하드코딩되어 있음. `.env` 파일이 버전 관리 시스템에 포함될 경우 민감 정보가 노출될 위험이 있음 |
| **근거** | 민감 정보를 담은 설정 파일은 `.gitignore`에 반드시 포함되어야 하며, 경로 명시보다 환경 변수 직접 주입 방식이 더 안전함 |
| **수정 방향** | `.gitignore`에 `.env` 추가 여부를 확인하고, CI/CD 환경에서는 시스템 환경 변수로 직접 주입하는 방식 권장 |

---

## 3. 종합 요약

| 구분 | 건수 |
|------|------|
| 스타일 지적 사항 | 7건 |
| 보안 취약점 (높음) | 1건 |
| 보안 취약점 (중간) | 3건 |
| 보안 취약점 (낮음) | 1건 |
| **합계** | **12건** |

가장 우선적으로 처리해야 할 항목은 **V-02 (IP 주소 미검증)** 와 **V-04 (파일명 경로 순회)** 이며, 스타일 측면에서는 **S-07 (오타 `nomaly`)** 이 런타임 동작에 직접 영향을 줄 수 있으므로 즉시 수정이 필요합니다.
