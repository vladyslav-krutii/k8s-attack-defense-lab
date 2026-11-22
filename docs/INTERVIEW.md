# Підготовка до співбесіди: k8s-attack-defense-lab

Шпаргалка для співбесіди на DevSecOps-стажування: історія на 3 хвилини,
шість сценаріїв у п'яти рядках кожен, найважчі знахідки, 20 типових
запитань з короткими відповідями і план живого демо. Деталі й докази — у
[THREAT_MODEL.md](THREAT_MODEL.md), [README](../README.md) і
[LEARNING.md](LEARNING.md). Цифри — з CI-запуску
[44936598909](https://github.com/vladyslav-krutii/k8s-attack-defense-lab/actions/runs/44936598909).

## Історія проєкту за 3 хвилини

**Проблема (20 с).** Про безпеку Kubernetes легко говорити списком
«best practices». Я хотів *показати* кожну практику: ось мисконфігурація,
ось атака, яка через неї працює, ось контроль, який її блокує, і тест, що
це доводить. Не «я налаштував PSA», а «без PSA web читає PKI kubelet, з PSA
— ні, і CI перевіряє це на кожен push».

**Що побудував (60 с).**
- **Один застосунок, два деплої.** nginx `web` → Node.js `api` → Postgres
  `db` на kind з Calico. Kustomize: спільна `base`, оверлей **vulnerable**
  з шістьма реалістичними помилками і **hardened** з шістьма шарами
  захисту.
- **Шість сценаріїв**: privileged + hostPath, токен ServiceAccount з
  `edit`, відсутність NetworkPolicy, пароль у ConfigMap і env, root з
  записуваною FS без лімітів, змінні теги образів. Кожен має `run.sh`
  (мінімальне безпечне демо) і `verify.sh` з кодами 0 / 1 / 2:
  EXPLOITABLE / BLOCKED / INCONCLUSIVE.
- **Admission control.** Kyverno 1.20, 9 CEL `ValidatingPolicy`. Кожна є в
  audit- і enforce-варіанті, вибір — міткою namespace. 105 офлайн-тестів.
- **Runtime detection.** Falco на `modern_ebpf` без `privileged`, шість
  власних правил з перевіркою «має спрацювати / має мовчати» на обох
  оверлеях.
- **CI.** static (kubeconform, `kyverno test`, shellcheck, gitleaks,
  `trivy config`), image (trivy за digest + SBOM) і e2e: увесь лаб з нуля
  на kind у GitHub Actions за ~5 хв. Вимога: 6/6 EXPLOITABLE на vulnerable
  і 6/6 BLOCKED на hardened.

**Найцікавіше (80 с).** Найбільше навчили не атаки, а налагодження:
- **Kyverno reports-controller** перезапускався 22 рази з exit 0. Це був не
  OOM-kill, а пам'ять на межі ліміту: процес зависав і втрачав leader
  lease.
- **Правило Falco мовчало**, бо стандартне правило спрацьовувало першим
  (`rule_matching: first`).
- **Алерт з `l4=udp` для curl**: musl робить `connect()` UDP-сокета, не
  надсилаючи жодного пакета.
- **`kind load` і digest**: kubelet не знаходив образ за `@sha256`, а
  BuildKit міняв digest з кожною збіркою.

**Чого навчився (20 с).** Контроль без тесту — це припущення. І тест
захисту має спершу перевірити, що застосунок працює, інакше зламаний
застосунок виглядає як «заблоковано». А детекція потрібна саме там, де
превенція чесно не закриває дірку: exec з `/tmp` на emptyDir.

## Шість сценаріїв по п'ять рядків

| # | Мисконфігурація | Вплив | Фікс (шар) | Політика Kyverno | Детекція Falco |
|---|---|---|---|---|---|
| 1 | `privileged`, root, `hostPath: /` | FS вузла, PKI kubelet → вузол і API | PSA `restricted` + securityContext | `disallow-privileged-containers`, `disallow-host-path`, `require-run-as-nonroot` | правило 2 (PKI), правило 1 (shell) |
| 2 | SA з `edit`, токен автомонтується | читає всі Secret у namespace | свій SA, без токена, без RoleBinding | — (RBAC не admission-питання) | правило 2 (токен), правило 3 (web → API) |
| 3 | немає NetworkPolicy | web → `db:5432` в обхід api | default-deny + явні дозволи | — | правило 3 |
| 4 | пароль у ConfigMap і env | `view` читає пароль; `printenv` | Secret як файл 0440, `*_FILE` | `disallow-secrets-in-env`, `disallow-secrets-in-configmaps` | правило 4 (`/proc/*/environ`) |
| 5 | root, rw root FS, без лімітів | закинутий інструмент, DoS вузла | read-only FS, emptyDir з `sizeLimit`, ліміти | `require-readonly-rootfs`, `require-resource-limits` | правила 5 і 6 |
| 6 | образ за тегом `latest` | підмінений образ після рестарту | `name:tag@sha256:…` | `require-image-digest`, `disallow-latest-tag` | немає: runtime-сигналу нема |

Чесні межі: сценарій 4 — застосунок усе ще читає свій файл; сценарій 5 —
exec з `/tmp` (emptyDir не буває `noexec`), закриває правило 6; сценарій 6
— digest не каже, *хто* зібрав образ (підпис — сценарій 7).

## Найважчі знахідки

### 1. Kyverno reports-controller: 22 «тихі» рестарти

- **Симптом.** `make reports` падав на таймауті з 0 звітів. Контролер мав
  22 рестарти, статус `Completed`, exit 0. На OOM не схоже.
- **Діагноз.**
  - Логи: «Failed to renew lease», потім «leadership lost» і вихід:
    контролер завершується сам, коли втрачає лідерство.
  - API-сервер здоровий (`/readyz` за 0,27 с), інші контролери не
    падають.
  - Cgroup контейнера на вузлі (`docker exec k8s-lab-worker`):
    `memory.current` 127Mi з ліміту 128Mi, `memory.events max` росте на
    ~150/с. Ядро постійно відбирає пам'ять, процес зависає і не встигає
    оновити lease. OOM-kill не настає, тому `OOMKilled` у статусі немає.
  - Тригер: фонова перевірка Cosign-підпису SecScan (інший проєкт у тому
    ж кластері) плюс 18 об'єктів політик лаби.
- **Фікс.** Ліміт 512Mi у `cluster/kyverno/values.yaml`. Після цього
  `make reports` закінчився за 67 с; на hardened 8 PASS / 0 FAIL.
- **Урок.** Exit 0 не означає «все добре». Тиск пам'яті видно в
  `memory.events` і `memory.pressure`, а не в статусі пода.

### 2. musl і UDP `connect()`: хибний алерт Falco

- **Симптом.** Алерт правила 3 показував
  `10.244.x.x:34106->10.96.0.1:443 l4=udp process=curl`, хоча curl ходить
  до API-сервера по TCP.
- **Експеримент.** `curl https://10.96.0.1` (за IP) дав одну TCP-подію, а
  `curl https://kubernetes.default.svc` (за ім'ям) — UDP і TCP. Отже,
  поле правильне, а правило ловило не ту подію.
- **Пояснення.** `getaddrinfo()` у musl робить `connect()` UDP-сокета до
  кожної знайденої адреси, щоб дізнатися адресу джерела (сортування за RFC
  6724). Пакет не відправляється.
- **Фікс.** Правило 3 рахує лише TCP `connect()`; UDP-egress лишається за
  default-deny NetworkPolicy. Лічильник на vulnerable впав з 8 до 5.
- **Урок.** Syscall — не те саме, що мережевий трафік. Перш ніж правити
  умову, з'ясуй експериментом, що саме бачить сенсор.

### 3. Falco: правило «затінене» стандартним (`rule_matching`)

- **Симптом.** Власне правило 3 мовчало на web → API-сервер, хоча умова
  була правильна.
- **Причина.** За замовчуванням `rule_matching: first`: стандартне правило
  «Unexpected connection to K8s API Server» завантажується раніше,
  спрацьовує першим, і далі Falco подію не перевіряє.
- **Фікс.** `rule_matching: all` у values Falco. Ціна — трохи CPU на подію.
- **Урок.** Правило, яке ніхто не перевірив на реальній атаці, — лише
  гіпотеза. Тому `make verify-detection` перевіряє кожне правило на обох
  оверлеях.

### 4. Port-forward «пробиває» default-deny

- **Факт (перевірено 2026-11-22 на hardened).** Зсередини кластера web →
  `db:5432` — BLOCKED. А `kubectl port-forward deploy/db 15432:5432` з
  хоста підключився до Postgres.
- **Пояснення.** kubelet підключається до порту зсередини мережевого
  namespace пода. Трафік не йде мережею подів, тож NetworkPolicy (Calico)
  його не бачить.
- **Висновок.** Доступ через port-forward — питання RBAC
  (`pods/portforward`), а не мережі. У `view` цього права немає:
  `auth can-i create pods/portforward --as-group=lab:developers` → `no`.
  Записано в прийнятих ризиках threat model.

### 5. Асинхронні PolicyReport: «PASS 0» одразу після деплою

- **Симптом.** Одразу після `make hardened` звіти показували `PASS 0`.
- **Пояснення.** Результати enforce-політик не пишуться під час admission.
  Їх додає background scan через кілька секунд, до хвилини. А ресурс, що
  порушує enforce, взагалі не створюється, тож і звіту про нього немає.
- **Фікс.** `policy-reports.sh` чекає, доки кожен Deployment, ReplicaSet і
  Pod матиме звіт з результатом від кожної політики, що стосується подів.
  Число обчислюється з кластера, не зашите.
- **Урок.** Доказ блокування — відмова в admission (`verify-admission`,
  15/15), а не звіт. І на асинхронну систему чекають умовою, а не
  `sleep 60`.

### 6. shellcheck: 28 зауважень і один справжній баг

- **Що знайшов.** Format-рядок `printf` у `verify-detection.sh` мав п'ять
  полів на чотири аргументи (SC2183), тож заголовок таблиці друкувався з
  зайвою порожньою колонкою. Баг дрібний, але справжній, і жоден тест його
  не ловив.
- **Решта.** `cd … || exit 2`, `if out=$(cmd); then` замість `$?`, helper
  `join_list`. Кожне навмисне SC2016 (скрипт в одинарних лапках
  розкривається *у контейнері*) має причину поруч.
- **Урок.** Лінтер корисний, лише коли його вивід чистий: 28 «звичних»
  зауважень ховають 29-те, справжнє. Тому disable — точково і з причиною,
  а не глобально в `.shellcheckrc`.

**Ще коротко, якщо буде час:**
- `kind load` реєструє образ лише під тегом, тож kubelet не знаходив
  `@sha256` і йшов на Docker Hub. Фікс — `render-pinned.sh` додає
  digest-ім'я на кожному вузлі.
- BuildKit provenance змінював digest з кожною збіркою; рішення —
  `--provenance=false` локально.
- `grep` без збігів під `pipefail` тихо обривав скрипт.
- Busybox вибирає аплет за `argv[0]`, тож «blocked» для `/tmp` був
  артефактом тесту, а не захистом.
- e2e у CI впав через порядок кроків: `verify-all` забруднював вікно
  старту для `verify-detection`.
- Гонка webhook Kyverno: поди Ready, а webhook ще не відповідає; `make
  policies` тепер повторює ідемпотентний apply.

## 20 запитань і короткі відповіді

### Kubernetes і hardening

1. **Чим PSA відрізняється від Kyverno і навіщо обидва?** — PSA — вбудовані
   профілі (privileged / baseline / restricted) на рівні namespace. Kyverno
   додає власні правила: digest образів, ліміти, секрети в env. Обидва —
   defense in depth: `verify-admission` доводить, що Kyverno сам блокує под
   сценарію 1 у namespace без PSA.
2. **Чому мало прибрати RoleBinding, треба ще вимкнути автомонтування
   токена?** — Токен у поді — це ідентичність. Без RBAC сьогодні він нічого
   не може, але завтра хтось прив'яже роль до `default` або до цього SA.
   Без токена красти нічого.
3. **Requests vs limits?** — Request — резерв для шедулера, не стеля.
   Limit — стеля: для пам'яті перевищення означає OOM-kill, для CPU —
   throttling.
4. **Чому `readOnlyRootFilesystem` не заважає запустити закинутий
   бінарник?** — Записувані emptyDir лишаються, а `noexec` для emptyDir
   Kubernetes не підтримує. Read-only FS захищає образ, а не «будь-який
   exec». Решту закривають distroless і правило Falco 6.
5. **Чому секрет у env гірший за секрет у файлі?** — Env копіюється всюди:
   дочірні процеси, `/proc/<pid>/environ`, дампи падінь, логи
   налагодження. А ConfigMap читає роль `view`, яку роздають щедро. Файл
   0440 читає лише власник і група пода, і його можна ротувати без
   рестарту.
6. **У NetworkPolicy `namespaceSelector` і `podSelector` — AND чи OR?** — В
   одному елементі `from`/`to` — AND, у двох окремих — OR. Класична
   помилка, що відкриває весь namespace.
7. **Навіщо закріплювати PSA `enforce-version`?** — Щоб оновлення кластера
   не зламало деплой раптово. `warn` і `audit` на `latest` попереджають про
   нові порушення заздалегідь.

### Admission і detection

8. **Fail-open чи fail-closed webhook?** — Fail-open: падіння Kyverno
   (або атака на нього) тихо вимикає всі політики. Fail-closed: «немає
   рішення — немає admission». Ціна — треба виключити інфраструктурні
   namespace, інакше вийде deadlock (Kyverno потребує мережі подів,
   мережа — `calico-node`). Виключення компенсує RBAC.
9. **Як вводити політики в живий кластер?** — Audit → виправити маніфести
   → enforce. Я так і зробив: `require-resource-limits` була в audit, доки
   hardened-маніфести не отримали ліміти. Інакше політика блокує власний
   застосунок.
10. **Чому звіт Kyverno не доводить, що enforce блокує?** — Порушник не
    створюється, тож звіту про нього немає, а звіти асинхронні. Доказ — це
    відмова в admission: `verify-admission`, 15 кейсів.
11. **Admission vs runtime detection?** — Admission бачить YAML у момент
    створення. Що відбувається *всередині* контейнера потім (shell, читання
    токена, з'єднання), бачить лише runtime-сенсор. Потрібні обидва.
12. **Як ти тестуєш правила детекції?** — На обох оверлеях: має
    спрацювати на атаку і мовчати там, де атака неможлива. Плюс два вікна
    хибних спрацювань: старт застосунку і звичайний трафік.
13. **Алерт на hardened — це погано?** — Не завжди. Правило 1 (shell)
    спрацьовує, бо shell справді запустився: hardening не забирає
    `pods/exec` і не прибирає shell з образу. Тиша тут була б сліпою
    плямою.
14. **Чому Falco без `privileged`?** — Сенсор бачить кожен syscall на
    вузлі, тож він сам ціль. З `modern_ebpf` вистачає чотирьох capabilities
    (BPF, PERFMON, SYS_RESOURCE, SYS_PTRACE). Модуль ядра не потрібен.

### Supply chain і CI

15. **Digest vs тег, і від чого digest НЕ захищає?** — Тег — покажчик, його
    пересуває будь-хто з правом push; навіть `1.2.3` змінний. Digest — хеш
    вмісту. Але digest не каже, *хто* зібрав образ: для цього потрібен
    підпис (Cosign) і перевірка identity.
16. **Як у CI перевірити, що vulnerable *лишається* вразливим?** —
    Протилежні гейти: `trivy config` мусить знайти HIGH у vulnerable (11) і
    нічого MEDIUM+ у hardened; e2e — `verify-all --expect exploitable` і
    `--expect blocked`. «Чистий» vulnerable означає, що зламалось демо або
    сканер.
17. **Навіщо пінити actions по SHA і версії інструментів?** — Тег action
    можна пересунути на чужий код, який виконається з нашим токеном.
    Інструменти ставляться з перевіркою SHA-256, образи — за digest. Плюс
    `permissions: {}` і `contents: read` на job.
18. **Що робиш, коли сканер знаходить HIGH?** — Спершу шукаю справжній
    фікс: 6 HIGH CVE в npm я закрив, прибравши npm з runtime-образу, а не
    через ignore. Якщо приймаю ризик — запис з причиною
    (`.trivyignore.yaml`, KSV-0125).
19. **Чому `verify.sh` має три коди, а не два?** — Бо «не вдалося
    підключитися до db» нічого не доводить, якщо застосунок зламаний.
    Спочатку контроль (web → api працює), і лише тоді невдача атаки —
    BLOCKED. Інакше — INCONCLUSIVE.

### Підсумок

20. **Що зробив би далі для продакшену?** — Сценарій 7: SSRF у SecScan →
    Kubernetes API, з `ImageValidatingPolicy` для підпису Cosign. Cosign
    для образу лаби через локальний реєстр. Falcosidekick для алертів у
    Slack чи SIEM. 3 репліки Kyverno з PDB. Distroless-образи, щоб правило
    1 мовчало, і GitOps замість ручного `make hardened`.

## Живе демо (5 хвилин)

Підготовка: кластер уже створений (`make cluster kyverno policies
falco`), вкладка з логами Falco (`make falco-logs`).

1. **(1 хв) vulnerable.** `make vulnerable && make verify-detection`, потім
   `bash scripts/verify-all.sh --expect exploitable`: шість EXPLOITABLE з
   поясненням. Показати `make scenario-1`: web читає FS вузла через
   `/host`.
2. **(1 хв) Одна атака детально.** `make scenario-4`: пароль видно під
   роллю `view` у ConfigMap і в `printenv`. У вкладці Falco — алерт
   правила 4.
3. **(1,5 хв) hardened.** `make hardened && make verify-detection && make
   smoke`, потім `verify-all --expect blocked`: шість BLOCKED, і застосунок
   працює. Пояснити, чому правила 1, 4 і 6 все одно спрацьовують.
4. **(1 хв) Admission.** `make verify-admission`: 15 кейсів, у кожного
   DENIED видно, яка саме політика відмовила.
5. **(0,5 хв) CI.** GitHub Actions: три job-и, у e2e ті самі таблиці. Звідки
   цифри в README.

## Чесно про обмеження (якщо спитають «що не так»)

- Exec з `/tmp` на emptyDir не блокується, лише детектується (правило 6).
- Немає перевірки підпису образів: digest без identity.
- Одна репліка Kyverno, fail-closed; інфраструктурні namespace виключені.
- Port-forward обходить NetworkPolicy; контролюється RBAC.
- Застосунок сам читає свій пароль; краще — короткоживучі облікові дані.
- Повний список — у
  [THREAT_MODEL.md](THREAT_MODEL.md#accepted-risks-and-known-limits).
