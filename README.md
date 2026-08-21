# NexCache VERA M3.3 (NVIDIA Rubin Architecture)

[Italiano](#italiano) | [English](#english)

---

<a name="italiano"></a>
## 🇮🇹 Versione Italiana

### Visione e Obiettivo del Progetto
Benvenuti nel repository di **NexCache VERA M3.3**. Questo progetto è il culmine di una ricerca approfondita sull'architettura ad altissime prestazioni per motori In-Memory Data Store, specificamente ottimizzati per l'hardware di nuova generazione **NVIDIA Rubin-class**.

L'obiettivo è creare un engine che non sia solo "veloce", ma **architettonicamente superiore**, sfruttando le istruzioni vettoriali SVE2, l'allineamento a 256 byte (Rubin-Mode) e una topologia a 176 shard per eliminare ogni collo di bottiglia di sincronizzazione.

### Chi sono: Giuseppe Lobbene
Sono **Giuseppe Lobbene**, un informatico pervaso da una profonda e radicata passione per l'ingegneria del software, oggi potenziata dall'Intelligenza Artificiale. Amo addentrarmi nelle basi profonde dei progetti, studiarne la meccanica e sperimentare soluzioni innovative che possano superare i limiti delle performance attuali.

La mia storia riflette quella di molti professionisti in Italia: un paese meraviglioso dove però il mercato dell'IT è spesso vincolato a sistemi rigidi, lenti e talvolta obsoleti. Troppo spesso il merito e l'iniziativa proattiva vengono soffocati da logiche di sfruttamento o di "sostituibilità" delle risorse umane.

Oggi, la mia ricerca non è solo tecnologica ma di vita. Cerco una stabilità professionale che mi permetta di apprendere costantemente, restando al passo con l'innovazione, per garantire un futuro degno alla mia famiglia e al mio piccolo **Oliver**, nato da pochi mesi. Questo progetto è la mia "firma" nel mondo dell'IT: una prova tangibile che la passione, unita allo studio costante, può generare eccellenza tecnologica anche partendo da sfide personali difficili.

### Architettura e Implementazione (VERA M3.3)
Questo progetto introduce innovazioni critiche nel kernel di NexCache:

*   **Rubin-Mode Alignment (256-byte):** Ogni struttura critica (Arena, Object, MPSC Queue) è allineata a 256 byte per coincidere perfettamente con la dimensione del settore di memoria del processore NVIDIA Rubin, eliminando il false sharing.
*   **176-Shard Topology:** L'engine è partizionato in 176 shard logici, mappati sull'hardware per permettere un accesso parallelo senza lock (G3-GODMODE).
*   **Vyukov MPSC Lock-Free Queue:** Utilizziamo code Multi-Producer Single-Consumer lock-free per il dispatching dei comandi dai thread di networking ai worker thread, minimizzando la contesa sui bus di sistema.
*   **SVE2 Vectorized Parsing:** Il parsing del protocollo RESP è accelerato tramite istruzioni ARM SVE2, processando multipli delimitatori simultaneamente in un unico ciclo di clock.
*   **SVI (Small-Value Inlining):** Per valori piccoli, i dati vengono inlined direttamente nell'oggetto (serverObject), riducendo le dereferenziazioni di puntatori e migliorando il cache hit rate.

### Performance: confronto con i competitor

**Aggiornamento**: una sessione successiva ha trovato e corretto un bug reale — 8 thread "worker" di un motore multi-thread mai completato (`core/engine.c`) giravano in busy-spin permanente, consumando ~350% di CPU **anche a server completamente inattivo**, pur non elaborando mai un solo comando (verificato: la funzione che avrebbe dovuto instradare lavoro verso quei thread non aveva alcun chiamante in tutto il codebase). Su una macchina condivisa, questo penalizzava **anche** le misure di Redis/Garnet nello stesso confronto, non solo NexCache — i numeri della tabella precedente (in fondo a questa sezione, mantenuti per trasparenza) erano quindi falsati, non solo pessimistici. Disattivarli ha dato **+59,9%** di throughput da solo; un secondo fix (embedding SVI chiave+valore, prima solo valore) ha aggiunto un altro **+7,2%**.

Nuova misura, dopo i fix, su ambiente riproducibile: GitHub Actions (`ubuntu-22.04`), Redis **8.0.1 compilato da sorgente** (l'apt di Ubuntu 22.04 offre solo 6.0.16), `redis-benchmark` con la stessa metodologia di prima (200.000 richieste, 50 connessioni, valori da 32 byte, nessun pipelining).

| Workload | Redis 8.0.1 | NexCache VERAM3.3 |
|---|---|---|
| SET puro (ops/sec) | 54.810 | 55.571 (**101%**) |
| GET puro a caldo (ops/sec) | 55.249 | 55.325 (**100%**) |
| Latenza p50 SET (ms) | 0,447 | 0,447–0,455 |
| Latenza p50 GET (ms) | 0,447 | 0,447 |

**Nota metodologica, per onestà**: anche i runner di GitHub Actions sono macchine virtuali cloud condivise, non hardware dedicato — non il picco teorico assoluto, ma un ambiente riproducibile e uguale per entrambi i server nello stesso momento (a differenza della vecchia misura macOS, qui non c'è più l'asimmetria di rumore descritta sopra). **Sotto pipeline profonda** (molti comandi in sequenza senza attendere risposta, che espone il costo per-operazione invece della latenza di rete) il divario reale emerge: NexCache è al 62-64% di Redis sul SET e al 76-82% sul GET — l'oggetto di lavoro futuro documentato in [issue #1](https://github.com/lobbenedesign/nexcache-VERAM3.3/issues/1).

I numeri Garnet non sono stati ri-misurati in questa sessione (richiede un SDK .NET non disponibile sull'ambiente di test); la tabella storica sotto resta come riferimento ma va considerata superata per la colonna NexCache.

<details>
<summary>Misura storica (macOS, prima dei fix — mantenuta per trasparenza)</summary>

Misurato con `redis-benchmark` (200.000 richieste, 50 connessioni, valori da 32 byte, keyspace caldo per i GET) contro Redis 8.0.1 e Microsoft Garnet, un server alla volta sulla stessa macchina di sviluppo (macOS ARM64, Apple Silicon).

**Nota metodologica importante, per onestà**: questa non è una macchina da benchmark dedicata — è la mia macchina di sviluppo quotidiana, con altre applicazioni attive durante la misura (load average ~7-8 su rilevazioni multiple). I numeri assoluti vanno quindi letti come **indicativi**, non come picco teorico. È stato osservato che VERAM3.3 è più sensibile al rumore di sistema rispetto a Redis e Garnet (varianza fino al 30% tra run consecutivi, vs <15% per gli altri due) — poi scoperto essere in gran parte dovuto al bug degli 8 thread parassiti descritto sopra, non (solo) al polling dei thread I/O legittimi.

| Workload | Redis 8.0.1 | Garnet | NexCache VERAM3.3 |
|---|---|---|---|
| SET puro (ops/sec) | 88.456 | 84.926 (96%) | 25.860–33.557 (29–38%, alta varianza) |
| GET puro a caldo (ops/sec) | 81.566 | 87.184 (107%) | 40.088 (49%) |
| Latenza p50 SET (ms) | 0,223 | 0,239 | 0,799–0,831 |
| Latenza p50 GET (ms) | 0,247 | 0,239 | 0,687 |

</details>

### Architettura: differenze e similitudini con i competitor

| Aspetto | Redis 8.x | Microsoft Garnet | NexCache VERAM3.3 |
|---|---|---|---|
| Modello di concorrenza | Single-thread per lo storage classico + thread I/O opzionali per parsing/risposta | Multi-thread nativo, log ibrido epoch-based lock-free (Tsavorite) | Multi-thread: NexDash/NexSegcache a 176 shard + fast-path sui thread I/O per GET |
| Storage principale | Dizionario hash classico (dict.c), un solo lock implicito per shard di cluster | Hybrid log (RAM + SSD tiering nativo), append-only con GC epoch-based | NexSegcache (stringhe) + NexDashTable (tipi complessi), narrow-waist API comune |
| Path di lettura calda | Passa sempre dal loop dati principale | Lock-free diretto sul log in memoria | Bypassa il thread principale: risposta diretta dal thread I/O quando la chiave è nel fast-path |
| Path di scrittura | Passa sempre dal loop dati principale | Append lock-free al log | Invalidate-on-write + lazy read-through (niente doppia scrittura) |
| Sharding interno | Nessuno di default (cluster mode usa 16384 slot tra nodi, non thread) | Partizionamento per sessione/thread | 176 shard logici fissi, indicizzati con Fenwick tree per iterazione O(log n) |
| Persistenza | RDB snapshot + AOF | Nessuna persistenza nativa completa (checkpoint sperimentali) | RDB (formato "NEXCACHE", compatibile a livello di framing con REDIS/VALKEY legacy) |
| Replica | Sì, matura, PSYNC incrementale | Limitata | Sì (PSYNC2-style), fixata in questa sessione dopo un bug di framing RDB che la rendeva non funzionante |
| Feature avanzate native | Nessun vector search / CRDT / timeseries nativi | Nessuno di questi | Vector search (HNSW), CRDT (OR-Set/G-Counter/PN-Counter), timeseries, stream a credito, esposti come moduli RESP caricabili |
| Allineamento hardware | Generico | Generico | Allineamento a 256 byte pensato per architetture NVIDIA Rubin-class; probe runtime per SVE2/AVX invece di flag di build fissi |

**Similitudini**: tutti e tre parlano il protocollo RESP e sono quindi drop-in compatibili a livello client; tutti e tre puntano a ridurre la contesa sul path caldo (Redis con IO-thread opzionali, Garnet con un log lock-free, VERAM3.3 con sharding + fast-path). **Differenza sostanziale**: Redis resta deliberatamente single-thread sul cuore dei dati per semplicità/prevedibilità; Garnet e VERAM3.3 scelgono entrambi il multi-threading nativo, ma con strategie diverse — log unico lock-free (Garnet) contro sharding esplicito a grana fine + fast-path di lettura (VERAM3.3).

---

<a name="english"></a>
## 🇺🇸 English Version

### Project Vision and Goal
Welcome to the **NexCache VERA M3.3** repository. This project is the result of rigorous research into high-performance architectures for In-Memory Data Stores, specifically optimized for the next-generation **NVIDIA Rubin-class** hardware.

The goal is to build an engine that is not just "fast," but **architecturally superior**, utilizing SVE2 vector instructions, 256-byte alignment (Rubin-Mode), and a 176-shard topology to eliminate synchronization bottlenecks.

### About Me: Giuseppe Lobbene
I am **Giuseppe Lobbene**, a computer scientist driven by a deep and rooted passion for software engineering, now enhanced by Artificial Intelligence. I love diving into the core foundations of projects, studying their inner mechanics, and experimenting with innovative solutions that push the boundaries of current performance.

My story mirrors that of many IT professionals in Italy: a beautiful country where the IT market is often constrained by rigid, slow, and sometimes obsolete systems. Too often, merit and proactive initiative are stifled by exploitation or the perception of human resources as "replaceable."

Today, my quest is not just technological but vital. I am looking for a professional stability that allows me to constantly learn and stay ahead of innovation, to ensure a dignified future for my family and my little son **Oliver**, born just a few months ago. This project is my "signature" in the IT world: tangible proof that passion, combined with constant study, can generate technological excellence even when facing difficult personal challenges.

### Architecture and Implementation (VERA M3.3)
This project introduces critical innovations into the NexCache kernel:

*   **Rubin-Mode Alignment (256-byte):** Every critical structure (Arena, Object, MPSC Queue) is aligned to 256 bytes to perfectly match the memory sector size of the NVIDIA Rubin processor, eliminating false sharing.
*   **176-Shard Topology:** The engine is partitioned into 176 logical shards, mapped onto the hardware to allow lock-free parallel access (G3-GODMODE).
*   **Vyukov MPSC Lock-Free Queue:** We use lock-free Multi-Producer Single-Consumer queues for command dispatching from networking threads to worker threads, minimizing system bus contention.
*   **SVE2 Vectorized Parsing:** RESP protocol parsing is accelerated via ARM SVE2 instructions, processing multiple delimiters simultaneously in a single clock cycle.
*   **SVI (Small-Value Inlining):** For small values, data is inlined directly within the object (serverObject), reducing pointer dereferencing and improving cache hit rates.

### Performance: comparison against competitors

**Update**: a later session found and fixed a real bug — 8 "worker" threads belonging to a never-finished multi-thread engine (`core/engine.c`) were permanently busy-spinning, burning ~350% CPU **even on a completely idle server**, while never actually processing a single command (verified: the function meant to dispatch work to them had no callers anywhere in the codebase). On a shared machine, this also penalized the Redis/Garnet measurements in the same comparison, not just NexCache's — the table further down (kept for transparency) was therefore skewed, not just pessimistic. Disabling them alone gave **+59.9%** throughput; a second fix (embedding key+value together in SVI, instead of value only) added another **+7.2%**.

New measurement, after the fixes, on a reproducible environment: GitHub Actions (`ubuntu-22.04`), Redis **8.0.1 built from source** (Ubuntu 22.04's apt package is only 6.0.16), `redis-benchmark` with the same methodology as before (200,000 requests, 50 connections, 32-byte values, no pipelining).

| Workload | Redis 8.0.1 | NexCache VERAM3.3 |
|---|---|---|
| SET-only (ops/sec) | 54,810 | 55,571 (**101%**) |
| GET-only, warm (ops/sec) | 55,249 | 55,325 (**100%**) |
| SET p50 latency (ms) | 0.447 | 0.447–0.455 |
| GET p50 latency (ms) | 0.447 | 0.447 |

**Methodology note, for honesty's sake**: GitHub Actions runners are also shared cloud VMs, not dedicated hardware -- not the absolute theoretical peak, but a reproducible environment, identical for both servers at the same time (unlike the old macOS measurement, there's no longer the noise asymmetry described below). **Under deep pipelining** (many commands back-to-back with no wait for a reply, which exposes per-operation cost rather than network latency) the real gap shows up: NexCache is at 62-64% of Redis on SET and 76-82% on GET -- tracked as future work in [issue #1](https://github.com/lobbenedesign/nexcache-VERAM3.3/issues/1).

Garnet numbers were not re-measured in this session (needs a .NET SDK not available in the test environment); the historical table below is kept as a reference but should be considered superseded for the NexCache column.

<details>
<summary>Historical measurement (macOS, before the fixes -- kept for transparency)</summary>

Measured with `redis-benchmark` (200,000 requests, 50 connections, 32-byte values, warm keyspace for GETs) against Redis 8.0.1 and Microsoft Garnet, one server at a time on the same development machine (macOS ARM64, Apple Silicon).

**Important methodology note, for honesty's sake**: this is not a dedicated benchmark rig — it's my everyday development machine, with other applications running during the measurement (load average ~7-8 across multiple checks). The absolute numbers should be read as **indicative**, not a theoretical ceiling. VERAM3.3 was observed to be more sensitive to system noise than Redis and Garnet (up to 30% variance between consecutive runs, vs <15% for the other two) — later found to be largely caused by the 8 parasitic threads bug described above, not (only) legitimate I/O-thread polling.

| Workload | Redis 8.0.1 | Garnet | NexCache VERAM3.3 |
|---|---|---|---|
| SET-only (ops/sec) | 88,456 | 84,926 (96%) | 25,860–33,557 (29–38%, high variance) |
| GET-only, warm (ops/sec) | 81,566 | 87,184 (107%) | 40,088 (49%) |
| SET p50 latency (ms) | 0.223 | 0.239 | 0.799–0.831 |
| GET p50 latency (ms) | 0.247 | 0.239 | 0.687 |

</details>

### Architecture: differences and similarities with competitors

| Aspect | Redis 8.x | Microsoft Garnet | NexCache VERAM3.3 |
|---|---|---|---|
| Concurrency model | Single-thread for classic storage + optional I/O threads for parsing/reply | Native multi-thread, epoch-based lock-free hybrid log (Tsavorite) | Multi-thread: 176-shard NexDash/NexSegcache + I/O-thread fast-path for GET |
| Primary storage | Classic hash dict (dict.c), one implicit lock per cluster shard | Hybrid log (native RAM + SSD tiering), append-only with epoch-based GC | NexSegcache (strings) + NexDashTable (complex types), shared narrow-waist API |
| Hot read path | Always goes through the main data loop | Direct lock-free access to the in-memory log | Bypasses the main thread: direct reply from the I/O thread when the key is on the fast-path |
| Hot write path | Always goes through the main data loop | Lock-free append to the log | Invalidate-on-write + lazy read-through (no double write) |
| Internal sharding | None by default (cluster mode uses 16384 slots across nodes, not threads) | Partitioned per session/thread | 176 fixed logical shards, indexed with a Fenwick tree for O(log n) iteration |
| Persistence | RDB snapshot + AOF | No full native persistence (experimental checkpointing) | RDB ("NEXCACHE" format, framing-compatible with legacy REDIS/VALKEY) |
| Replication | Yes, mature, incremental PSYNC | Limited | Yes (PSYNC2-style), fixed in this session after an RDB framing bug that made it entirely non-functional |
| Native advanced features | No native vector search / CRDTs / timeseries | None of these | Vector search (HNSW), CRDTs (OR-Set/G-Counter/PN-Counter), timeseries, credit-based streams, exposed as loadable RESP modules |
| Hardware alignment | Generic | Generic | 256-byte alignment designed for NVIDIA Rubin-class architectures; runtime probing for SVE2/AVX instead of fixed build flags |

**Similarities**: all three speak the RESP protocol and are therefore drop-in compatible at the client level; all three aim to reduce contention on the hot path (Redis with optional I/O threads, Garnet with a lock-free log, VERAM3.3 with sharding + fast-path). **Key difference**: Redis deliberately stays single-threaded at the core of the data path for simplicity and predictability; Garnet and VERAM3.3 both choose native multi-threading, but with different strategies — a single lock-free log (Garnet) versus explicit fine-grained sharding + a read fast-path (VERAM3.3).

---
*Created with passion by Giuseppe Lobbene.*
