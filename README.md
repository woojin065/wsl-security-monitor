# WSL Security Monitor

개발용 WSL과 Docker, 지정한 프로젝트를 읽기 전용으로 점검하는 로컬 서비스입니다.
**점검 결과·근거·해결 방법과 에이전트에 붙여 넣을 지시문**을 제공합니다. 자동 수정은 하지 않습니다.

## 시작하기

Ubuntu/WSL2, Python 3.11 이상, 활성화된 systemd 사용자 관리자가 필요합니다.
Python 표준 라이브러리만 사용하며 pip, Node, npm 설치는 필요 없습니다.

```bash
git clone https://github.com/woojin065/wsl-security-monitor.git
cd wsl-security-monitor
python3 install.py
loginctl enable-linger "$USER"
```

`loginctl enable-linger`는 로그인 세션이 닫혀도 WSL이 실행 중인 동안 사용자 서비스를 유지하고 부팅 시 시작하게 합니다.
환경에 따라 권한이 필요할 수 있습니다. WSL 자체를 시작하는 Windows 작업은 등록하지 않습니다.

브라우저에서 **http://localhost:8765** 를 엽니다.

1. **프로젝트 검사 설정**에서 검사할 폴더를 한 줄에 하나씩 지정하고 저장합니다.
2. 사설 패키지 이름을 외부에 보내고 싶지 않다면 외부 조회 제외 목록에 넣거나 외부 조회를 끕니다.
3. **지금 점검**을 누릅니다. 처음에는 WSL·Docker만 검사하며 프로젝트 경로를 지정해야 개발 프로젝트 검사가 실행됩니다.
4. 문제의 근거와 해결 방법을 읽고 **해결 지시문 복사**를 누릅니다.
5. 여러 문제는 체크한 뒤 **선택한 문제 지시문 복사**로 한 번에 전달할 수 있습니다.
6. 에이전트에서 변경·승인·검증을 진행한 다음 다시 점검합니다.

클립보드 권한이 없으면 지시문을 선택해 복사하는 창이 열립니다.
웹 화면은 한국 시간으로 표시하며 점검 중에도 이력을 볼 수 있습니다.

## 예약 실행

- 최초 설정 생성 날짜를 기준으로 **이틀 간격, 오전 9시 Asia/Seoul**에 실행합니다.
- systemd 타이머는 매일 오전 9시에 실행되고 점검기가 기준 날짜와 날짜 차이를 확인합니다.
  월별 홀수 날짜 방식과 달리 월이 바뀌어도 이틀 간격이 유지됩니다.
- `Persistent=false`: WSL이 꺼져 있던 시각의 점검을 부팅 후 보충하지 않습니다.
- 사용자 systemd 관리자가 실행 중이어야 합니다. `Linger=yes`로 유지합니다.
- 수동 점검은 예약 기준 날짜에 영향을 주지 않습니다.
- 타이머에는 매일의 다음 실행이 표시되지만 화면에는 실제 다음 점검 날짜가 표시됩니다.
- 실행 정확도는 1분이며 suspend/resume 동작은 OS 타이머 동작에 따릅니다. WSL을 종료한 경우의 누락 보충은 비활성화되어 있습니다.

```bash
systemctl --user status wsl-security-monitor.service wsl-security-scan.timer
systemctl --user list-timers wsl-security-scan.timer
journalctl --user -u wsl-security-monitor.service -u wsl-security-scan.service
```

systemd 없이 수동 실행하려면:

```bash
python3 -m monitor serve
python3 -m monitor scan
```

`python3 -m monitor serve --port 8766`으로 수동 실행 포트를 바꿀 수 있습니다.

## 검사 범위

| 영역 | 검사 | 한계 |
| --- | --- | --- |
| 수신 포트 | TCP·UDP 전체 인터페이스 바인딩 | Windows 방화벽·실제 원격 접근 가능 여부는 미검사 |
| 서비스 | 실행 중인 서비스의 제한된 위험 목록 | 악성 프로세스 전체 탐지 기능이 아님 |
| 권한 | `.ssh`, `.aws` 디렉터리, SSH 파일, `gh` 자격증명 파일 권한 | 자격증명 파일 내용을 읽지 않음; AWS 내부 개별 파일 권한은 미검사 |
| SSH | 활성 ssh.service의 기본 유효 인증 설정 | 권한 부족은 미완료; 사용자·주소별 Match 설정은 별도 확인 |
| 보안 업데이트 | 로컬 APT 캐시의 보안 업데이트 후보, 변경되는 저장소의 Date·Valid-Until, 자동 갱신 성공 기록(존재 시) | 정적 Ubuntu 기본 저장소의 발행 시각은 갱신 실패로 판정하지 않음; 마지막 전체 갱신 성공은 확정할 수 없음; `apt update`와 설치를 실행하지 않음 |
| Docker | 실행 중 컨테이너의 privileged, host network, 추가 capability, 민감 경로 마운트, 전체 인터페이스 포트 | 환경 변수·로그·이미지 파일을 읽지 않음; 중지 컨테이너·이미지 CVE 미검사 |
| 비밀정보 | 개인 키, GitHub 토큰, AWS 접근 키 식별자, 비밀값 할당 패턴, Git 추적 환경 파일 | 패턴 기반으로 오탐·미탐 가능; Git 과거 이력 미검사 |
| 의존성 | npm package-lock.json, 고정 버전 requirements.txt, uv.lock, poetry.lock의 OSV 조회 | 미지원 잠금 형식·버전 범위·조건부 설치 해석·설치 환경은 미검사 |

프로젝트 검사는 홈 아래의 명시적으로 지정한 디렉터리에만 적용됩니다.
홈 전체, 자격증명 디렉터리, 심볼릭 링크 경로는 설정에서 거부합니다.
`.git`, `node_modules`, `.venv`, `venv`, 빌드·캐시·자격증명 폴더와 심볼릭 링크는 건너뜁니다.
1MiB 초과 파일과 바이너리는 건너뛰고 결과에 제외 수를 표시합니다.
프로젝트당 후보 파일 10,000개, 전체 발견 2,000개와 시간 한도를 두며 초과하면 미완료 처리합니다.
의존성은 잠금 파일당 최대 500개와 조회 시간 한도가 있습니다. 미완료는 안전을 뜻하지 않습니다.

SSH의 `known_hosts`와 표준 백업 `known_hosts.old`는 호스트 공개 키 목록으로 취급하며,
다른 사용자의 쓰기 권한을 경고합니다. 개인 키 등 민감한 파일은 다른 사용자의 읽기 권한도 경고합니다.
APT 메타데이터의 발행 시각과 로컬 갱신 실행 시각은 서로 다릅니다.
Ubuntu 정적 기본 저장소를 제외한 메타데이터는 발행 후 3일 이상 지났거나 유효기간이 만료되면 확인을 요청합니다.
자동 갱신 성공 기록이 없으면 마지막 전체 갱신 성공 시각은 알 수 없다고 표시합니다.

## 데이터와 외부 통신

**검사 대상의 소스 코드·파일 내용·비밀값을 외부에 전송하지 않습니다.**

- 외부 조회 목적지는 `https://api.osv.dev/v1/query` 하나입니다.
- 요청은 패키지 생태계(`npm`/`PyPI`), 패키지 이름, 고정 버전만으로 새로 구성합니다.
- 잠금 파일 원문, `resolved` URL, 경로, 프로젝트 이름, 토큰을 요청에 넣지 않습니다.
- 프록시 환경 변수를 적용하지 않고 HTTP 리다이렉트도 따르지 않습니다.
- 사설 패키지는 이름 자체가 민감할 수 있습니다. 제외 목록에는 `패키지명` 또는 `생태계:패키지명`을 지정하세요.
- 외부 조회를 끄면 OSV 통신을 하지 않습니다. 그 경우 의존성 검사는 미완료로 표시됩니다.
- OSV 응답에서 공지 ID와 수정 버전 후보만 사용하며 원격 상세 설명을 저장하지 않습니다.
- 비밀정보 발견 시 경로·행 번호·패턴 종류만 저장하고 원문·비밀값은 저장하지 않습니다.
- 에이전트용 복사문은 로컬 브라우저에서 만듭니다. 외부 에이전트에 붙여 넣는 동작은 사용자가 수행합니다.
- 이 저장소에는 모니터 서비스 소스와 테스트만 올립니다. 점검 대상 프로젝트·설정·점검 결과는 GitHub에 올리지 않습니다.

설정·점검 결과는 `~/.local/share/wsl-security-monitor/`에 저장합니다.
상태 디렉터리는 `700`, 새 상태 파일은 `600`이며 최신 100회 결과만 보관합니다.
같은 사용자 계정의 다른 프로그램과 관리자에게는 접근이 가능하므로 계정 자체의 격리 기능은 아닙니다.
테스트용 상태 위치는 `WSM_STATE_DIR` 환경 변수로 지정할 수 있습니다.

웹 서버는 `127.0.0.1`에만 바인딩합니다. 외부 자산·분석 스크립트·CDN을 사용하지 않습니다.
Host 검증, 쓰기 요청의 Origin·CSRF 토큰 검증, CSP, 저장 캐시 비활성화를 적용합니다.
로컬 사용자 접근을 위한 서비스이며 인터넷·공유 네트워크로 포트 전달해서 운영하는 구성은 지원하지 않습니다.

## 검증과 관리

```bash
python3 -m unittest discover -s tests -v
node tests/test_ui.js
```

테스트는 비밀값 비저장, 외부 조회 필드 제한, 프록시·리다이렉트 차단, 파일 제외,
프로젝트 범위, 요청 출처 검증, 날짜 간격, 중복 점검 방지를 확인합니다.
복사 기능 테스트만 선택적으로 Node.js가 필요합니다. 실행 서비스에는 Node.js가 필요하지 않습니다.
실제 환경에서는 웹 HTTP 응답, 서비스·타이머 상태, 읽기 전용 점검과 공개 패키지 OSV 응답을 확인합니다.

소스 변경 후 웹 서비스를 다시 시작합니다:

```bash
systemctl --user restart wsl-security-monitor.service
```

서비스를 중지·해제하려면:

```bash
systemctl --user disable --now wsl-security-monitor.service wsl-security-scan.timer
```

사용자 unit 파일은 `~/.config/systemd/user/wsl-security-*`에 있습니다.
서비스 해제는 로컬 점검 기록이나 linger 설정을 삭제하지 않습니다.
linger 해제는 다른 사용자 서비스에도 영향을 줄 수 있으므로 별도로 판단하세요.

## 참고 자료

- [OSV API](https://google.github.io/osv.dev/api/): 패키지 이름·버전 기반 취약점 조회
- [systemd.timer](https://www.freedesktop.org/software/systemd/man/latest/systemd.timer.html): OnCalendar, Persistent, AccuracySec

이 서비스는 정해진 범위의 위험 신호를 수집합니다. 검사 결과에 문제가 없더라도 시스템 전체의 안전을 보증하지 않습니다.
