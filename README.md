# **SoK: Cyber Reasoning Framework**


## **Table of Contents**

### **1. Data Acquisition / Telemetry [20]** 
### **2. Data Engineering / Representation [19]** 
### **3. Reasoning / Inference [54]**  
### **4. Orchestration / Decision [14]**  
### **5. Application / Analyst Interaction [20]** 
### **6. Math behind the Causal Reasoning [14]**  
### **7. Application of  Causal Inference [25]** 
### **8. LLM with Causal Reasoning [37]** 
 
---

## 1. Data Acquisition / Telemetry

### Observability Pipelines and Signal Correlation
1. **ZeroTracer: In-Band eBPF-Based Trace Generator With Zero Instrumentation for Microservice Systems** (2025) — *IEEE Transactions on Parallel and Distributed Systems* (Institute of Electrical and Electronics Engineers).  
   **Task:** Distributed tracing & observability | **System:** Zero-instrumentation causal request tracing | **Data:** eBPF-generated HTTP traces, microservice runtime events | **DOI:** https://doi.org/10.1109/TPDS.2025.3571934

1. **Open tracing tools: Overview and critical comparison** (2023) — *Journal of Systems and Software* (Elsevier Science Inc.).
   **Task:** system observability and tracing | **Survey:** Compare and evaluate open tracing tools | **Data:** telemetry data, multivocal literature sources | **DOI:** [https://doi.org/10.1016/j.jss.2023.111793](https://doi.org/10.1016/j.jss.2023.111793)

1. **OpenNOP: an open-source network observability platform enabling multi-vendor multi-layer monitoring and ML analysis** (2025) — *Journal of Optical Communications and Networking* (Optica Publishing Group).  
   **Task:** Network observability & fault detection | **System:** Open-source multi-layer observability with ML inference | **Data:** L1/L2/L3 network telemetry, time-series metrics, disturbance labels | **DOI:** https://doi.org/10.1364/JOCN.560632
1. **On Multilateral Security Monitoring and Analysis With an Abstract Tomogram of Network Flows** (2018) — *IEEE Access* (Institute of Electrical and Electronics Engineers).  
   **Task:** Network security monitoring & visual analytics | **System:** Tomogram-based visualization and causal flow analysis | **Data:** Network flow records, co-occurrence statistics, sequence-mined flow events | **DOI:** https://doi.org/10.1109/ACCESS.2018.2829910
1. **Provenance-based Intrusion Detection Systems: A Survey** (2022) — *ACM Computing Surveys* (Association for Computing Machinery).  
   **Task:** Host-based intrusion detection | **Survey:** Review provenance-based IDS techniques and taxonomies | **Data:** System-level data provenance graphs (DAGs), surveyed IDS datasets | **DOI:** https://doi.org/10.1145/3539605

1. **Security Approaches for Data Provenance in the Internet of Things: A Systematic Literature Review** (2025) — *ACM Computing Surveys* (Association for Computing Machinery).  
   **Task:** IoT security & data provenance | **Survey:** Systematically review provenance techniques for securing IoT data | **Data:** Surveyed IoT provenance mechanisms, security requirements, performance metrics, provenance graphs | **DOI:** https://doi.org/10.1145/3718735
1. **Practical Whole-System Provenance Capture** (2017) — *Proceedings of the 2017 Symposium on Cloud Computing (SoCC ’17)* (Association for Computing Machinery).  
   **Task:** System provenance collection & security monitoring | **System:** CamFlow for efficient whole-system provenance capture | **Data:** Kernel-level events, information-flow provenance graphs, distributed system traces | **DOI:** https://doi.org/10.1145/3127479.3129249
1. **Host-Based Intrusion Detection System With System Calls: Review and Future Trends** (2018) — *ACM Computing Surveys* (Association for Computing Machinery).  
   **Task:** Host-based intrusion detection | **Survey:** Review system-call-based HIDS methods and future trends | **Data:** System call traces, HIDS benchmark datasets, feature extraction techniques | **DOI:** https://doi.org/10.1145/3214304
1. **AXI-REALM: Safe, Modular and Lightweight Traffic Monitoring and Regulation for Heterogeneous Mixed-Criticality Systems** (2025) — *IEEE Transactions on Computers* (Institute of Electrical and Electronics Engineers).  
   **Task:** Real-time traffic monitoring & regulation in mixed-criticality systems | **System:** Hardware-based interconnect monitoring and regulation for predictability and safety | **Data:** Interconnect traffic traces, bandwidth and latency metrics, mixed-criticality workload measurements | **DOI:** https://doi.org/10.1109/TC.2025.3584530

1. **BTM: Topic Modeling over Short Texts** (2014) — *IEEE Transactions on Knowledge and Data Engineering* (Institute of Electrical and Electronics Engineers).
   **Task:** topic modeling | **Method:** Model corpus-level biterm co-occurrences for short texts | **Data:** short text corpora, word co-occurrence biterms | **DOI:** [https://doi.org/10.1109/TKDE.2014.2313872](https://doi.org/10.1109/TKDE.2014.2313872)

### Trust, Data Integrity, and Adversary Resistance
1. **Intel Software Guard Extensions Applications: A Survey** (2023) — *ACM Computing Surveys* (Association for Computing Machinery).  
   **Task:** Hardware-based security & trusted execution | **Survey:** Categorize applications and limitations of Intel SGX | **Data:** Surveyed SGX-based systems, application categories, security properties | **DOI:** https://doi.org/10.1145/3593021

### Datasets
1. **A Dataset for Cyber Threat Intelligence Modeling of Connected Autonomous Vehicles** (2025) — *Scientific Data* (Springer Nature).  
   **Task:** Cyber threat intelligence modeling for autonomous vehicles | **Dataset:** Curated CTI dataset for connected and autonomous vehicles | **Data:** Vehicle network telemetry, threat intelligence annotations, attack scenarios | **DOI:** https://doi.org/10.1038/s41597-025-04439-5

1. **The 1999 DARPA Off-Line Intrusion Detection Evaluation** (2000) — *Computer Networks* (Elsevier).  
   **Task:** Intrusion detection evaluation & benchmarking | **Benchmark:** Evaluate IDS techniques using DARPA datasets | **Data:** DARPA 1999 intrusion detection datasets, network traffic traces, labeled attack scenarios | **DOI:** https://doi.org/10.1016/S1389-1286(00)00139-0

1. **ICS-LTU2022: A Dataset for ICS Vulnerabilities** (2025) — *Computers & Security* (Elsevier).  
   **Task:** Industrial Control Systems (ICS) security analysis | **Dataset:** Curated vulnerability dataset for ICS environments | **Data:** ICS vulnerability records, CVE mappings, system and protocol attributes | **DOI:** https://doi.org/10.1016/j.cose.2024.104143

1. **Testing Intrusion Detection Systems: A Critique of the 1998 and 1999 DARPA Intrusion Detection System Evaluations as Performed by Lincoln Laboratory** (2000) — *ACM Transactions on Information and System Security* (Association for Computing Machinery).  
   **Task:** Intrusion detection evaluation & benchmarking | **Evaluation:** Critically analyze DARPA IDS evaluation methodology | **Data:** DARPA 1998–1999 IDS evaluation datasets, ROC-based performance results | **DOI:** https://doi.org/10.1145/382912.382923

1. **UNSW-NB15: A Comprehensive Data Set for Network Intrusion Detection Systems** (2015) — *Proceedings of the 2015 Military Communications and Information Systems Conference (MilCIS 2015)* (IEEE).  
   **Task:** Network intrusion detection evaluation | **Dataset:** Benchmark dataset for modern NIDS research | **Data:** PCAP network traffic, extracted flow features, labeled low-footprint attack scenarios | **DOI:** https://doi.org/10.1109/MilCIS.2015.7348942

1. **Toward developing a systematic approach to generate benchmark datasets for intrusion detection** (2012) — *Computers & Security* (Elsevier).
   **Task:** intrusion detection | **Dataset:** Systematically generate benchmark IDS datasets | **Data:** synthetic network traffic, labeled intrusion scenarios | **DOI:** [https://doi.org/10.1016/j.cose.2011.12.012](https://doi.org/10.1016/j.cose.2011.12.012)
1. **A Review of the Advancement in Intrusion Detection Datasets** (2020) — *Procedia Computer Science* (Elsevier).
   **Task:** intrusion detection | **Survey:** Review and analyze IDS dataset evolution | **Data:** benchmark intrusion detection datasets | **DOI:** [https://doi.org/10.1016/j.procs.2020.03.330](https://doi.org/10.1016/j.procs.2020.03.330)

1. **Intrusion detection system for wireless mesh network using multiple support vector machine classifiers with genetic-algorithm-based feature selection** (2018) — *Computers & Security* (Elsevier).
   **Task:** intrusion detection | **Method:** IDS using multi-SVM with GA-based feature selection | **Data:** wireless mesh network traffic, intrusion detection datasets | **DOI:** [https://doi.org/10.1016/j.cose.2018.04.010](https://doi.org/10.1016/j.cose.2018.04.010)

1. **Generation of a new IDS test dataset: Time to retire the KDD collection** (2013) — *IEEE Wireless Communications and Networking Conference (WCNC)* (Institute of Electrical and Electronics Engineers).
   **Task:** intrusion detection | **Dataset:** Propose modern benchmark IDS dataset | **Data:** contemporary network traffic, modern attack scenarios | **DOI:** [https://doi.org/10.1109/WCNC.2013.6555301](https://doi.org/10.1109/WCNC.2013.6555301)

---

## 2. Data Engineering / Representation

### Event normalization
1. **MITRE ATT&CK: State of the Art and Way Forward** (2024) — *ACM Computing Surveys* (Association for Computing Machinery).  
   **Task:** Threat analysis & threat modeling | **Survey:** Systematize research leveraging the MITRE ATT&CK framework | **Data:** MITRE ATT&CK techniques, surveyed research studies, auxiliary threat intelligence data | **DOI:** https://doi.org/10.1145/3687300
1. **Systematic Literature Review of Security Event Correlation Methods** (2022) — *IEEE Access* (Institute of Electrical and Electronics Engineers).  
   **Task:** Security event correlation | **Survey:** Review and categorize event correlation methods | **Data:** Security alerts, event correlation techniques, evaluation datasets | **DOI:** https://doi.org/10.1109/ACCESS.2022.3168976
 1. **Debiasing Android Malware Datasets: How Can I Trust Your Results If Your Dataset Is Biased?** (2022) — *IEEE Transactions on Information Forensics and Security* (Institute of Electrical and Electronics Engineers).  
   **Task:** Android malware detection & dataset curation | **Method:** Debias malware datasets for reliable ML evaluation | **Data:** Android malware and goodware datasets, representative unlabeled corpora | **DOI:** https://doi.org/10.1109/TIFS.2022.3180184
 
### Schema design
1. **Causality-based Feature Selection: Methods and Evaluations** (2020) — *ACM Computing Surveys* (Association for Computing Machinery).
   **Task:** feature selection | **Survey:** Review and evaluate causality-based feature selection | **Data:** synthetic datasets, real-world datasets | **DOI:** [https://doi.org/10.1145/3409382](https://doi.org/10.1145/3409382)

1. **Local Causal and Markov Blanket Induction for Causal Discovery and Feature Selection for Classification Part II: Analysis and Extensions** (2010) — *Journal of Machine Learning Research* (JMLR.org).
   **Task:** causal discovery and feature selection | **Method:** Analyze and extend local causal and Markov blanket induction | **Data:** observational data, classification datasets | **DOI:** [https://doi.org/10.5555/1756006.1756014](https://doi.org/10.5555/1756006.1756014)

1. **Learning high-dimensional directed acyclic graphs with latent and selection variables** (2012) — *The Annals of Statistics* (Institute of Mathematical Statistics).
   **Task:** causal discovery | **Method:** Learn DAGs with latent and selection variables | **Data:** high-dimensional observational data with latent and selection variables | **DOI:** [https://doi.org/10.1214/11-AOS940](https://doi.org/10.1214/11-AOS940)

1. **Computational Methods of Feature Selection** (2007) — *Computational Methods of Feature Selection* (Chapman and Hall/CRC).
   **Task:** feature selection | **Survey:** Compile computational methods for feature selection | **Data:** NA | **DOI:** [https://doi.org/10.1201/9781584888796](https://doi.org/10.1201/9781584888796)

1. **Using Feature Selection for Local Causal Structure Learning** (2021) — *IEEE Transactions on Emerging Topics in Computational Intelligence* (Institute of Electrical and Electronics Engineers).
   **Task:** local causal structure learning | **Method:** Learn local causal structure via feature selection | **Data:** benchmark Bayesian network datasets | **DOI:** [https://doi.org/10.1109/TETCI.2020.2978238](https://doi.org/10.1109/TETCI.2020.2978238)

1. **An intrusion detection system using network traffic profiling and online sequential extreme learning machine** (2015) — *Expert Systems with Applications* (Elsevier).
   **Task:** intrusion detection | **Method:** Detect intrusions via traffic profiling and OS-ELM | **Data:** network traffic features, benchmark intrusion datasets | **DOI:** [https://doi.org/10.1016/j.eswa.2015.07.015](https://doi.org/10.1016/j.eswa.2015.07.015)

1. **A novel feature-selection approach based on the cuttlefish optimization algorithm for intrusion detection systems** (2015) — *Expert Systems with Applications* (Elsevier).
   **Task:** intrusion detection | **Method:** Select IDS features via cuttlefish optimization | **Data:** network traffic features, intrusion detection datasets | **DOI:** [https://doi.org/10.1016/j.eswa.2014.11.009](https://doi.org/10.1016/j.eswa.2014.11.009)

1. **Feature selection based on hybridization of genetic algorithm and particle swarm optimization** (2015) — *IEEE Geoscience and Remote Sensing Letters* (Institute of Electrical and Electronics Engineers).
   **Task:** feature selection | **Method:** Hybrid GA–PSO for automatic feature selection | **Data:** Indian Pines hyperspectral dataset, road detection imagery | **DOI:** [https://doi.org/10.1109/LGRS.2014.2337320](https://doi.org/10.1109/LGRS.2014.2337320)

### Knowledge graph construction
1. **DeepAG: Attack Graph Construction and Threats Prediction With Bi-Directional Deep Learning** (2022) — *IEEE Transactions on Dependable and Secure Computing* (Institute of Electrical and Electronics Engineers).  
   **Task:** Attack graph analysis & threat prediction | **Method:** Bi-directional deep learning for attack graph prediction | **Data:** System logs, attack sequences, attack graphs | **DOI:** https://doi.org/10.1109/TDSC.2022.3143551

1. **A Survey of MulVAL Extensions and Their Attack Scenarios Coverage** (2023) — *IEEE Access* (Institute of Electrical and Electronics Engineers).  
   **Task:** Attack graph analysis | **Survey:** Review MulVAL extensions and scenario coverage | **Data:** Logical attack graphs, MulVAL interaction rules, MITRE ATT&CK mappings | **DOI:** https://doi.org/10.1109/ACCESS.2023.3257721
1. **Cyberattack Graph Modeling for Visual Analytics** (2023) — *IEEE Access* (Institute of Electrical and Electronics Engineers).  
   **Task:** Attack graph analysis & visualization | **System:** Visual analytics for cyberattack graphs | **Data:** Honeynet attack data, cyberattack graphs | **DOI:** https://doi.org/10.1109/ACCESS.2023.3304640

1. **Alert-Driven Attack Graph Generation Using S-PDFA** (2021) — *IEEE Transactions on Dependable and Secure Computing* (Institute of Electrical and Electronics Engineers).  
   **Task:** Attack graph generation | **Method:** Generate attack graphs from alerts | **Data:** Security alerts, S-PDFA models, event sequences | **DOI:** https://doi.org/10.1109/TDSC.2021.3117348
1. **Knowledge-Enhanced Neurosymbolic Artificial Intelligence for Cybersecurity and Privacy** (2023) — *IEEE Internet Computing* (Institute of Electrical and Electronics Engineers).  
   **Task:** Cybersecurity & privacy intelligence | **Framework:** Knowledge-enhanced neurosymbolic AI for explainable security | **Data:** Security event data, domain knowledge graphs, neural feature representations | **DOI:** https://doi.org/10.1109/MIC.2023.3299435

### Semantic enrichment
1. **A Survey of Learning Causality with Data: Problems and Methods** (2020) — *ACM Computing Surveys* (Association for Computing Machinery).
   **Task:** causal learning | **Survey:** Review causal discovery and inference with big data | **Data:** NA | **DOI:** [https://doi.org/10.1145/3397269](https://doi.org/10.1145/3397269)

1. **Toward provably correct feature selection in arbitrary domains** (2009) — *Advances in Neural Information Processing Systems (NeurIPS 2009)* (Curran Associates Inc.).
   **Task:** feature selection | **Method:** Learn provably correct Markov boundaries | **Data:** artificial data, benchmark datasets, real-world datasets | **DOI:** [https://doi.org/10.5555/2984093.2984233](https://doi.org/10.5555/2984093.2984233)


### Multi-source data fusion
1. **Latent Semantic Analysis and Graph Theory for Alert Correlation: A Proposed Approach for IoT Botnet Detection** (2024) — *IEEE Open Journal of the Communications Society* (Institute of Electrical and Electronics Engineers).  
   **Task:** IoT botnet detection | **Method:** Alert correlation using LSA and graph theory | **Data:** IoT network traffic alerts, correlated alert graphs | **DOI:** https://doi.org/10.1109/OJCOMS.2024.3419570



---

## 3. Reasoning / Inference

### Causal inference & Probabilistic reasoning

1. **Multi-SpacePhish: Extending the Evasion-Space of Adversarial Attacks against Phishing Website Detectors Using Machine Learning** (2024) — *Digital Threats: Research and Practice* (Association for Computing Machinery).  
   **Task:** Phishing website detection & adversarial evaluation | **Attack:** Multi-space, realistic evasion attacks against ML-based PWD | **Data:** Phishing and benign websites, feature-space and problem-space perturbations, ML-PWD benchmarks | **DOI:** https://doi.org/10.1145/3638253

1. **Evidential Network Modeling for Cyber-Physical System State Inference** (2017) — *IEEE Access* (Institute of Electrical and Electronics Engineers).  
   **Task:** CPS security state inference | **Method:** Evidential network modeling for state reasoning | **Data:** Cyber-physical system observations, evidence variables | **DOI:** https://doi.org/10.1109/ACCESS.2017.2718498
1. **Dynamic Bayesian Networks for the Detection and Analysis of Cyber Attacks to Power Systems** (2025) — *IEEE Access* (Institute of Electrical and Electronics Engineers).  
   **Task:** Cyberattack detection & analysis for power systems | **Method:** Dynamic Bayesian network–based attack inference | **Data:** Power system measurements, cyber event observations | **DOI:** https://doi.org/10.1109/ACCESS.2025.3624345
1. **Nip in the Bud: Forecasting and Interpreting Post-Exploitation Attacks in Real-Time Through Cyber Threat Intelligence Reports** (2024) — *IEEE Transactions on Dependable and Secure Computing* (Institute of Electrical and Electronics Engineers).  
   **Task:** Threat intelligence analysis & attack forecasting | **Method:** Forecast post-exploitation attacks from CTI | **Data:** Cyber threat intelligence reports, APT behavior descriptions | **DOI:** https://doi.org/10.1109/TDSC.2024.3444781

1. **Security Risk Assessment Using Bayesian Attack Graphs and Complex Probabilities for Large Scale IoT Applications** (2025) — *IEEE Transactions on Dependable and Secure Computing* (Institute of Electrical and Electronics Engineers).   **Task:** Security risk assessment for IoT | **Method:** Bayesian attack graphs with complex probabilities | **Data:** IoT network topology, vulnerability data, attack paths | **DOI:** https://doi.org/10.1109/TDSC.2025.3597186

1. **Large-Scale Intranet Security Assessment Based on Bayesian Attack Graphs Using System Audit Logs** (2025) — *IEEE Transactions on Dependable and Secure Computing* (Institute of Electrical and Electronics Engineers).  
   **Task:** Intranet security assessment | **Method:** Bayesian attack graph analysis | **Data:** System audit logs, network configuration and vulnerability data | **DOI:** https://doi.org/10.1109/TDSC.2025.3642153
1. **Conditions and Assumptions for Constraint-Based Causal Structure Learning** (2022) — *Journal of Machine Learning Research* (JMLR.org).  
   **Task:** Causal discovery & structure learning | **Causal:** Formalize conditions for constraint-based causal graph recovery | **Data:** Observational data under structural causal models | **DOI:** https://doi.org/10.5555/3586589.3586698
1. **A Knowledge-Driven Approach to Threat Validation and Security Reasoning in Modular Systems** (2025) — *IEEE Access* (Institute of Electrical and Electronics Engineers).  
   **Task:** Threat validation & security reasoning | **Framework:** Knowledge-driven modular threat reasoning | **Data:** Modular system security knowledge, reasoning rules | **DOI:** https://doi.org/10.1109/ACCESS.2025.3602292

1. **Ensemble Technique of Intrusion Detection for IoT-Edge Platform** (2024) — *Scientific Reports* (Springer Nature).  
   **Task:** Intrusion detection for IoT-edge environments | **Method:** Ensemble-based IDS for improved detection accuracy | **Data:** IoT-edge network traffic, sensor telemetry, labeled attack datasets | **DOI:** https://doi.org/10.1038/s41598-024-62435-y
1. **Ranking-Enhanced Anomaly Detection Using Active Learning–Assisted Attention Adversarial Dual AutoEncoder** (2025) — *Scientific Reports* (Springer Nature).  
   **Task:** Anomaly detection in security monitoring | **Method:** Attention-based adversarial dual autoencoder with active learning | **Data:** Security event features, anomaly scores, actively labeled samples | **DOI:** https://doi.org/10.1038/s41598-025-25621-0
1. **ORTHRUS: Achieving High Quality of Attribution in Provenance-Based Intrusion Detection Systems** (2025) — *Proceedings of the 34th USENIX Security Symposium (SEC ’25)* (USENIX Association).  
   **Task:** Host-based intrusion detection & root-cause attribution | **Method:** GNN-based provenance IDS with high-quality attack attribution | **Data:** System-level data provenance graphs, OS event traces, attack dependency paths | **DOI:** NA
1. **Causal Analysis for Software-Defined Networking Attacks** (2021) — *Proceedings of the 30th USENIX Security Symposium (USENIX Security ’21)* (USENIX Association).  
   **Task:** SDN attack analysis & root-cause investigation | **Causal:** Perform causal analysis of SDN attacks and system behaviors | **Data:** SDN control-plane events, network state transitions, attack execution traces | **URL:**https://www.scopus.com/pages/publications/85114500204?inward

1. **Explainable Phishing Website Detection for Secure and Sustainable Cyber Infrastructure** (2025) — *Scientific Reports* (Springer Nature).  
   **Task:** Phishing website detection | **Method:** Explainable ML-based phishing detection | **Data:** Website URL features, content attributes, labeled phishing datasets | **DOI:** https://doi.org/10.1038/s41598-025-27984-w

1. **Detecting Cyber Attacks in Vehicle Networks Using Improved LSTM-Based Optimization Methodology** (2025) — *Scientific Reports* (Springer Nature).  
   **Task:** Vehicle network intrusion detection | **Method:** Optimized LSTM-based attack detection | **Data:** In-vehicle network traffic (e.g., CAN bus), attack traces, labeled datasets | **DOI:** https://doi.org/10.1038/s41598-025-04643-8
1. **A Causality-Aligned Structure Rationalization Scheme Against Adversarial Biased Perturbations for Graph Neural Networks** (2024) — *IEEE Transactions on Information Forensics and Security* (Institute of Electrical and Electronics Engineers).  
   **Task:** Adversarial robustness & secure graph learning | **Causal:** Learn invariant causal rationales for robust GNNs | **Data:** Graph-structured datasets with adversarial perturbations and OOD shifts | **DOI:** https://doi.org/10.1109/TIFS.2023.3318936

1. **Adversarial Attacks of Vision Tasks in the Past 10 Years: A Survey** (2025) — *ACM Computing Surveys* (Association for Computing Machinery).  
   **Task:** Adversarial robustness analysis for vision systems | **Survey:** Systematically review adversarial attacks on vision and LVLM tasks | **Data:** Surveyed vision benchmarks, adversarial attack methods, evaluation frameworks, LVLM attack scenarios | **DOI:** https://doi.org/10.1145/3743126

1. **SAM: Query-Efficient Adversarial Attacks against Graph Neural Networks** (2023) — *ACM Transactions on Privacy and Security* (Association for Computing Machinery).  
   **Task:** Adversarial attack analysis on graph learning systems | **Attack:** Query-efficient and stealthy graph-structure adversarial attacks | **Data:** Graph-structured datasets, node/edge perturbation scenarios, GNN benchmarks | **DOI:** https://doi.org/10.1145/3611307

1. **Untargeted Adversarial Attack on Knowledge Graph Embeddings** (2024) — *Proceedings of the 47th International ACM SIGIR Conference on Research and Development in Information Retrieval (SIGIR ’24)* (Association for Computing Machinery).  
   **Task:** Adversarial robustness analysis of knowledge graph embeddings | **Attack:** Untargeted, rule-based adversarial deletion and addition on KGs | **Data:** Knowledge graphs, learned logic rules, link prediction benchmark datasets | **DOI:** https://doi.org/10.1145/3626772.3657702

1. **Temporal Dynamics-Aware Adversarial Attacks on Discrete-Time Dynamic Graph Models** (2023) — *Proceedings of the 29th ACM SIGKDD Conference on Knowledge Discovery and Data Mining (KDD ’23)* (Association for Computing Machinery).  
   **Task:** Adversarial robustness of dynamic graph learning | **Attack:** Temporal dynamics–aware adversarial perturbations for dynamic graphs | **Data:** Discrete-time dynamic graph sequences, link prediction and node classification benchmarks | **DOI:** https://doi.org/10.1145/3580305.3599517


### ML/DL/RL
1. **Distributed Denial-of-Service (DDoS) Attack Detection Using Supervised Machine Learning Algorithms** (2025) — *Scientific Reports* (Springer Nature).  
   **Task:** DDoS attack detection | **Method:** Supervised machine learning–based traffic classification | **Data:** Network traffic features, labeled DDoS attack datasets | **DOI:** https://doi.org/10.1038/s41598-024-84879-y


1. **A Non-Markovian Game Approach on Labeled Attack Graphs for Security Decision-Making in Industrial Control Systems** (2025) — *IEEE Transactions on Information Forensics and Security* (Institute of Electrical and Electronics Engineers).  
   **Task:** Security decision-making for ICS | **Method:** Non-Markovian game-theoretic attack graph reasoning | **Data:** Labeled attack graphs, ICS topology and vulnerability data | **DOI:** https://doi.org/10.1109/TIFS.2025.3616599
1. **Adversarial Machine Learning Attacks and Defences in Multi-Agent Reinforcement Learning** (2025) — *ACM Computing Surveys* (Association for Computing Machinery).  
   **Task:** Adversarial ML analysis for multi-agent systems | **Survey:** Categorize attacks and defenses in MARL | **Data:** MARL/MAL/DRL attack models, defense techniques, evaluation settings | **DOI:** https://doi.org/10.1145/3708320

1. **Deep Reinforcement Learning–Based Intrusion Detection Scheme for Software-Defined Networking** (2025) — *Scientific Reports* (Springer Nature).  
   **Task:** Intrusion detection in SDN | **Method:** Deep reinforcement learning–based IDS | **Data:** SDN network traffic features, flow statistics, attack scenarios | **DOI:** https://doi.org/10.1038/s41598-025-24869-w
1. **Optimizing IoT Intrusion Detection With Cosine Similarity–Based Dataset Balancing and Hybrid Deep Learning** (2025) — *Scientific Reports* (Springer Nature).  
   **Task:** Intrusion detection in IoT networks | **Method:** Hybrid deep learning with cosine-similarity-based data balancing | **Data:** IoT intrusion detection datasets, balanced feature representations | **DOI:** https://doi.org/10.1038/s41598-025-15631-3

1. **Robust Genetic Machine Learning Ensemble Model for Intrusion Detection in Network Traffic** (2023) — *Scientific Reports* (Springer Nature).  
   **Task:** Network intrusion detection | **Method:** Genetic algorithm–optimized ML ensemble IDS | **Data:** Network traffic features, labeled intrusion datasets | **DOI:** https://doi.org/10.1038/s41598-023-43816-1
1. **Anomaly Detection in Encrypted Network Traffic Using Self-Supervised Learning** (2025) — *Scientific Reports* (Springer Nature).  
   **Task:** Encrypted traffic anomaly detection | **Method:** Self-supervised learning for traffic behavior modeling | **Data:** Encrypted network traffic features, flow metadata, anomaly labels | **DOI:** https://doi.org/10.1038/s41598-025-08568-0

1. **An Empirical Study on Unsupervised Network Anomaly Detection Using Generative Adversarial Networks** (2020) — *Proceedings of the 1st ACM Workshop on Security and Privacy on Artificial Intelligence (SPAI ’20)* (Association for Computing Machinery).  
   **Task:** Network anomaly detection | **Evaluation:** Empirically assess GAN-based unsupervised detection | **Data:** PCAP network traffic, synthetic traffic traces, statistical flow features | **DOI:** https://doi.org/10.1145/3385003.3410924

1. **Advanced Persistent Threat Detection Using Data Provenance and Metric Learning** (2023) — *IEEE Transactions on Dependable and Secure Computing* (Institute of Electrical and Electronics Engineers).  
   **Task:** Advanced persistent threat detection | **Method:** Provenance-graph feature extraction with online metric learning | **Data:** Host-level data provenance graphs, execution traces, labeled APT datasets | **DOI:** https://doi.org/10.1109/TDSC.2022.3221789

1. **Revolutionary Hybrid Ensembled Deep Learning Model for Accurate and Robust Side-Channel Attack Detection in Cloud Computing** (2025) — *Scientific Reports* (Springer Nature).  
   **Task:** Side-channel attack detection in cloud environments | **Method:** Hybrid ensemble deep learning for robust attack detection | **Data:** Cloud execution traces, side-channel leakage features, labeled attack scenarios | **DOI:** https://doi.org/10.1038/s41598-025-89794-4
1. **XAI-Driven Adversarial Attacks on Network Intrusion Detectors** (2024) — *Proceedings of the 2024 European Interdisciplinary Cybersecurity Conference (EICC ’24)* (Association for Computing Machinery).  
   **Task:** Network intrusion detection & adversarial evaluation | **Attack:** XAI-guided adversarial example generation against DL-based NIDS | **Data:** Real-world network traffic, NIDS features, explainability-derived feature attributions | **DOI:** https://doi.org/10.1145/3655693.3655714

1. **A Survey on Malware Detection Using Data Mining Techniques** (2017) — *ACM Computing Surveys* (Association for Computing Machinery).
   **Task:** malware detection | **Survey:** Review data-mining methods for malware detection | **Data:** malware samples, extracted static and dynamic features | **DOI:** [https://doi.org/10.1145/3073559](https://doi.org/10.1145/3073559)

1. **Anomaly-based network intrusion detection: Techniques, systems and challenges** (2009) — *Computers & Security* (Elsevier).
   **Task:** network intrusion detection | **Survey:** Review anomaly-based IDS techniques and challenges | **Data:** network traffic data, intrusion detection datasets | **DOI:** [https://doi.org/10.1016/j.cose.2008.08.003](https://doi.org/10.1016/j.cose.2008.08.003)

1. **A Survey of Data Mining and Machine Learning Methods for Cyber Security Intrusion Detection** (2016) — *IEEE Communications Surveys and Tutorials* (Institute of Electrical and Electronics Engineers).
   **Task:** intrusion detection | **Survey:** Review ML and data mining for cyber intrusion detection | **Data:** benchmark cyber security intrusion datasets | **DOI:** [https://doi.org/10.1109/COMST.2015.2494502](https://doi.org/10.1109/COMST.2015.2494502)


### Attack chain reconstruction
1. **A Data-Driven Approach to Prioritize MITRE ATT&CK Techniques for Active Directory Adversary Emulation** (2025) — *Scientific Reports* (Springer Nature).  
   **Task:** Adversary emulation & attack prioritisation | **Method:** Data-driven prioritisation of MITRE ATT&CK techniques | **Data:** Active Directory telemetry, ATT&CK technique mappings, emulation datasets | **DOI:** https://doi.org/10.1038/s41598-025-12948-x

1. **Latent Topic-Driven Cyber Intelligence Model for Tactics, Techniques, and Procedures (TTPs) Detection Using Hybrid Framework and Birch-Inspired Optimisation** (2025) — *Scientific Reports* (Springer Nature).  
   **Task:** Cyber threat intelligence & TTP detection | **Method:** Topic-model–driven CTI with hybrid optimisation | **Data:** Cyber threat reports, TTP annotations, textual intelligence corpora | **DOI:** https://doi.org/10.1038/s41598-025-27451-6
1. **Evaluating the Cybersecurity Risk of Real-World, Machine Learning Production Systems** (2023) — *ACM Computing Surveys* (Association for Computing Machinery).  
   **Task:** Security risk assessment of ML production systems | **Framework:** Threat modeling and attack-graph–based risk scoring for AML | **Data:** ML system assets, documented AML attack techniques, MulVAL attack graphs, expert-ranked risk attributes | **DOI:** https://doi.org/10.1145/3559104


### Root cause analysis
1. **Resilient Real-Time Network Anomaly Detection Using Novel Non-Parametric Statistical Tests** (2020) — *Computers & Security* (Elsevier).  
   **Task:** Real-time network anomaly detection | **Method:** Non-parametric statistical tests for resilient detection | **Data:** Network traffic statistics, streaming flow features | **DOI:** https://doi.org/10.1016/j.cose.2020.102146

1. **Machine Learning for Computer Systems and Networking: A Survey** (2022) — *ACM Computing Surveys* (Association for Computing Machinery).
   **Task:** machine learning for systems and networking | **Survey:** Review ML methods across systems and networking domains | **Data:** system traces, network measurements, operational datasets | **DOI:** [https://doi.org/10.1145/3523057](https://doi.org/10.1145/3523057)


### Neuro-symbolic reasoning
1. **Designing a Neuro-Symbolic Dual-Model Architecture for Explainable and Resilient Intrusion Detection in IoT Networks** (2025) — *Scientific Reports* (Springer Nature).  
   **Task:** Intrusion detection in IoT networks | **Method:** Neuro-symbolic dual-model IDS for explainability and resilience | **Data:** IoT network traffic features, attack traces, symbolic rules | **DOI:** https://doi.org/10.1038/s41598-025-27076-9
1. **Neurosymbolic AI in Cybersecurity: Bridging Pattern Recognition and Symbolic Reasoning** (2023) — *Proceedings of the IEEE Military Communications Conference (MILCOM 2023)* (Institute of Electrical and Electronics Engineers).  
   **Task:** Intrusion detection & cyber threat analysis | **Survey:** Examine neurosymbolic AI for interpretable and adaptive cybersecurity | **Data:** Security event data, IDS features, symbolic knowledge representations | **DOI:** https://doi.org/10.1109/MILCOM58377.2023.10356283

1. **Knowledge-Enhanced Neurosymbolic Artificial Intelligence for Cybersecurity and Privacy** (2023) — *IEEE Internet Computing* (Institute of Electrical and Electronics Engineers).  
   **Task:** Cybersecurity & privacy intelligence | **Framework:** Knowledge-enhanced neurosymbolic AI for explainable security | **Data:** Security event data, domain knowledge graphs, neural feature representations | **DOI:** https://doi.org/10.1109/MIC.2023.3299435
1. **A Neuro-Symbolic Classifier with Optimized Satisfiability for Monitoring Security Alerts in Network Traffic** (2022) — *Applied Sciences* (MDPI).  
   **Task:** Network security alert monitoring | **Method:** Neuro-symbolic classification with optimized satisfiability reasoning | **Data:** Network traffic features, security alerts, logical constraints | **DOI:** https://doi.org/10.3390/app122211502
1. **Neuro-Symbolic AI for Automated Cyber Threat Intelligence Generation** (2025) — *Proceedings of the 9th International Conference on Computing, Communication, Control and Automation (ICCCBEA 2025)* (IEEE).  
   **Task:** Automated cyber threat intelligence generation | **Method:** Neuro-symbolic AI combining GNNs, Transformers, and symbolic reasoning | **Data:** CIC-IDS2017, TON_IoT, BoT-IoT cybersecurity datasets | **DOI:** https://doi.org/10.1109/ICCUBEA65967.2025.11284257


### LLMs / Agents 
1. **Oedipus: LLM-Enhanced Reasoning CAPTCHA Solver** (2025) — *Proceedings of the 2025 ACM SIGSAC Conference on Computer and Communications Security (CCS ’25)* (Association for Computing Machinery).  
   **Task:** CAPTCHA security evaluation & attack automation | **Attack:** Decompose and solve reasoning CAPTCHAs using LLMs | **Data:** Reasoning CAPTCHA challenges, multimodal inputs, DSL-generated subtask traces | **DOI:** https://doi.org/10.1145/3719027.3744872
1. **Evaluating Generative Reasoning Models for Credential Tweaking and Lightweight Client-Side Defense in IoT Ecosystems** (2025) — *IEEE Internet of Things Journal* (Institute of Electrical and Electronics Engineers).  
   **Task:** IoT authentication defense & misuse detection | **Evaluation:** Assess generative reasoning models for credential attacks | **Data:** IoT credential data, simulated attack scenarios, client-side telemetry | **DOI:** https://doi.org/10.1109/JIOT.2025.3602717

1. **SECURE: Benchmarking Large Language Models for Cybersecurity** (2024) — *Annual Computer Security Applications Conference (ACSAC)* (Institute of Electrical and Electronics Engineers).
   **Task:** cybersecurity benchmarking | **Benchmark:** Evaluate LLM capabilities across diverse cybersecurity tasks and scenarios | **Data:** curated cybersecurity dataset, including Industrial Control System (ICS)–related contexts | **DOI:** [https://doi.org/10.1109/ACSAC63791.2024.00019](https://doi.org/10.1109/ACSAC63791.2024.00019)


1. **CASB Security Analytics for Encrypted SaaS Traffic: A Hybrid Transformer-Based Classification Framework in Enterprise Cloud Ecosystems** (2025) — *IEEE Access* (Institute of Electrical and Electronics Engineers).  
   **Task:** Cloud security analytics | **Method:** Transformer-based encrypted traffic classification | **Data:** Encrypted SaaS traffic features, enterprise cloud logs | **DOI:** https://doi.org/10.1109/ACCESS.2025.3642204
1. **Aligning DevOps and Microservice Architecture: Empirical Mapping, Taxonomy, and RAG-Based Decision Support** (2025) — *IEEE Access* (Institute of Electrical and Electronics Engineers).  
   **Task:** Architecture–operations alignment & decision support | **RAG:** Empirical DevOps–MSA mapping with retrieval-augmented reasoning | **Data:** Literature-derived DevOps–MSA concept pairs, taxonomy dataset, case-study evidence | **DOI:** https://doi.org/10.1109/ACCESS.2025.3628665
 
 1. **Lightweight Malicious URL Detection Using Deep Learning and Large Language Models** (2025) — *Scientific Reports* (Springer Nature).  
   **Task:** Malicious URL detection | **Method:** Lightweight DL and LLM-based URL classification | **Data:** URL lexical features, web metadata, labeled malicious/benign URL datasets | **DOI:** https://doi.org/10.1038/s41598-025-26653-2
1. **Single-Shot Black-Box Adversarial Attacks Against Malware Detectors: A Causal Language Model Approach** (2021) — *Proceedings of the IEEE International Conference on Intelligence and Security Informatics (ISI 2021)* (IEEE).  
   **Task:** Adversarial malware analysis & detector evasion | **Attack:** Single-shot black-box adversarial malware generation with causal language models | **Data:** Malware byte sequences, VirusTotal malware samples, evasion outcomes | **DOI:** https://doi.org/10.1109/ISI53945.2021.9624787

1. **Black-Box Adversarial Attacks Against Language Model Detector** (2023) — *Proceedings of the 12th International Symposium on Information and Communication Technology (SOICT ’23)* (Association for Computing Machinery).  
   **Task:** Adversarial evaluation of language model detectors | **Attack:** Black-box adversarial text attacks with semantic constraints | **Data:** Machine-generated and human-written text samples, adversarially perturbed texts | **DOI:** https://doi.org/10.1145/3628797.3628949

1. **The Emerged Security and Privacy of LLM Agent: A Survey with Case Studies** (2025) — *ACM Computing Surveys* (Association for Computing Machinery).
   **Task:** LLM agent security and privacy | **Survey:** Analyze threats, impacts, and defenses for LLM agents | **Data:** case studies, reported attacks and defenses from LLM agent literature | **DOI:** [https://doi.org/10.1145/3773080](https://doi.org/10.1145/3773080)

1. **Construction of Cyber-attack Attribution Framework Based on LLM** (2024) — *IEEE 23rd International Conference on Trust, Security and Privacy in Computing and Communications (TrustCom 2024)* (Institute of Electrical and Electronics Engineers).
   **Task:** cyber-attack attribution | **Framework:** Build hierarchical attribution framework using LLM-assisted report analysis | **Data:** cyber-attack attribution reports, network intrusion cases | **DOI:** [https://doi.org/10.1109/TrustCom63139.2024.00310](https://doi.org/10.1109/TrustCom63139.2024.00310)

1. **AI Agents Under Threat: A Survey of Key Security Challenges and Future Pathways** (2025) — *ACM Computing Surveys* (Association for Computing Machinery).
   **Task:** AI agent security | **Survey:** Systematically analyze threats, knowledge gaps, and future directions for securing AI agents | **Data:** surveyed literature on AI agents, threat models, and security mechanisms | **DOI:** [https://doi.org/10.1145/3716628](https://doi.org/10.1145/3716628)

---

## 4. Orchestration / Decision

### Playbooks

1. **Offensive Security Using Python: A Hands-On Guide to Offensive Tactics and Threat Mitigation Using Practical Strategies** (2024) — *Book* (Packt Publishing).  
   **Book:** Offensive security & threat mitigation | **Method:** Python-based exploitation and security automation | **Data:** Vulnerability data, exploit scripts, web and cloud security artifacts | **URL:** https://ieeexplore.ieee.org/document/10769418

1. **Model-Based Incident Response Playbooks** (2022) — *Proceedings of the 17th International Conference on Availability, Reliability and Security (ARES ’22)* (Association for Computing Machinery).  
   **Task:** Cyber incident response | **Framework:** Formal model-based design of incident response playbooks | **Data:** Incident response process models, playbook specifications | **DOI:** https://doi.org/10.1145/3538969.3538976

1. **Requirements for Playbook-Assisted Cyber Incident Response, Reporting and Automation** (2024) — *Digital Threats: Research and Practice* (Association for Computing Machinery).  
   **Task:** Cyber incident response & automation | **Framework:** Define requirements for machine-readable security playbooks | **Data:** Expert interview insights, incident response playbook structures | **DOI:** https://doi.org/10.1145/3688810



1. **On Collaboration and Automation in the Context of Threat Detection and Response with Privacy-Preserving Features** (2025) — *Digital Threats: Research and Practice* (Association for Computing Machinery).  
   **Task:** Threat detection & incident response automation | **Framework:** Collaborative and privacy-preserving detection and response architecture | **Data:** Shared threat intelligence, incident response data, privacy-preserving features | **DOI:** https://doi.org/10.1145/3707651
1. **ZenGuard: A Machine Learning–Based Zero Trust Framework for Context-Aware Threat Mitigation Using SIEM, SOAR, and UEBA** (2025) — *Scientific Reports* (Springer Nature).  
   **Task:** SOC threat detection & automated response | **System:** Zero Trust–based, ML-driven SIEM–SOAR–UEBA framework | **Data:** Enterprise SOC telemetry, SIEM/SOAR logs, UEBA behavioral features, synthetic behavior datasets | **DOI:** https://doi.org/10.1038/s41598-025-20998-4
1. **Security Monitoring with Wazuh: A Hands-On Guide to Effective Enterprise Security Using Real-Life Use Cases in Wazuh** (2024) — *Book* (Packt Publishing).  
   **Book:** SOC security monitoring & incident response | **System:** Open-source SIEM/SOAR-based security monitoring with Wazuh | **Data:** Host and network telemetry, IDS alerts, file integrity data, threat intelligence feeds, compliance logs | **URL:** https://ieeexplore.ieee.org/document/10769327

1. **AI4SOAR: A Security Intelligence Tool for Automated Incident Response** (2024) — *Proceedings of the 19th International Conference on Availability, Reliability and Security (ARES ’24)* (Association for Computing Machinery).  
   **Task:** Automated incident response | **System:** AI-assisted SOAR tool for playbook selection and execution | **Data:** Security alerts, SOAR playbooks, similarity-learning feature embeddings | **DOI:** https://doi.org/10.1145/3664476.3670450
1. **Automatic Incident Response Solutions: A Review of Proposed Solutions’ Input and Output** (2023) — *Proceedings of the 18th International Conference on Availability, Reliability and Security (ARES ’23)* (Association for Computing Machinery).  
   **Task:** Automated incident response | **Survey:** Review inputs and outputs of automatic response solutions | **Data:** Intrusion signals, asset inventories, platform monitoring data, network traffic, response actions mapped to D3FEND | **DOI:** https://doi.org/10.1145/3600160.3605066


### Policy engines
1. **Mitigate Data Poisoning Attack by Partially Federated Learning** (2023) — *Proceedings of the 18th International Conference on Availability, Reliability and Security (ARES ’23)* (Association for Computing Machinery).  
   **Task:** Malware detection & secure collaborative learning | **Defense:** Mitigate data poisoning via partially federated learning | **Data:** Behavioral malware graphs, distributed training data, label-flipping attack scenarios | **DOI:** https://doi.org/10.1145/3600160.3605032
1. **Taxonomy and Recent Advance of Game Theoretical Approaches in Adversarial Machine Learning: A Survey** (2023) — *ACM Transactions on Sensor Networks* (Association for Computing Machinery).  
   **Task:** Adversarial machine learning strategy analysis | **Survey:** Systematically review game-theoretic models for AML attacks and defenses | **Data:** Surveyed AML attack models (evasion, poisoning, backdoor), game formulations, evaluation metrics | **DOI:** https://doi.org/10.1145/3600094
1. **Hybrid MLOps Framework for Automated Lifecycle Management of Adaptive Phishing Detection Models** (2025) — *Scientific Reports* (Springer Nature).  
   **Task:** Phishing detection lifecycle management | **Framework:** Hybrid MLOps for adaptive, automated phishing model operations | **Data:** Phishing and benign website/email datasets, model performance logs, deployment telemetry | **DOI:** https://doi.org/10.1038/s41598-025-23600-z

### Closed-loop control systems
1. **Mitigating Propagation of Cyber-Attacks in Wide-Area Measurement Systems** (2024) — *IEEE Transactions on Information Forensics and Security* (Institute of Electrical and Electronics Engineers).  
   **Task:** Cyber-attack propagation mitigation in power grid monitoring systems | **Defense:** Learning-based defense and optimal communication reconfiguration | **Data:** WAMS communication graphs, PMU/PDC measurements, IEEE 14- and 30-bus test system simulations | **DOI:** https://doi.org/10.1109/TIFS.2024.3477269

### Reinforcement learning for response
1. **Offline Reinforcement Learning for Autonomous Cyber Defense Agents** (2025) — *Proceedings of the Winter Simulation Conference (WSC ’24)* (IEEE Press).  
   **Task:** Autonomous cyber defense & incident response | **Method:** Offline reinforcement learning for adaptive defense agents | **Data:** Simulated APT attack traces, cyber range telemetry, playbook execution logs | **DOI:** https://doi.org/10.5555/3712729.3712894

1. **Bridging Automated to Autonomous Cyber Defense: Foundational Analysis of Tabular Q-Learning** (2022) — *Proceedings of the 15th ACM Workshop on Artificial Intelligence and Security (AISec ’22)* (Association for Computing Machinery).  
   **Task:** Autonomous cyber defense & intrusion response | **Evaluation:** Analyze tabular Q-learning for defensive automation | **Data:** Simulated network scenarios, RL state–action–reward traces | **DOI:** https://doi.org/10.1145/3560830.3563732
1. **Secure Mechanism of Intelligent Urban Railway Cloud Platform Based on Zero-Trust Security Architecture** (2022) — *Proceedings of the 6th International Conference on High Performance Compilation, Computing and Communications (HP3C ’22)* (Association for Computing Machinery).  
   **Task:** Zero-trust security for critical infrastructure cloud platforms | **Framework:** Zero-trust architecture with self-learning trust management | **Data:** Railway cloud network telemetry, traffic states, trust profiles, simulation data | **DOI:** https://doi.org/10.1145/3546000.3546015




---

## 5. Application / Analyst Interaction

### Analyst workflows
1. **Alert Prioritisation in Security Operations Centres: A Systematic Survey on Criteria and Methods** (2024) — *ACM Computing Surveys* (Association for Computing Machinery).  
   **Task:** SOC alert prioritisation | **Survey:** Review criteria and methods for alert prioritisation with human–AI teaming | **Data:** SOC alert datasets, prioritisation criteria, automation and HAT methods | **DOI:** https://doi.org/10.1145/3695462

1. **Towards Human-AI Teaming to Mitigate Alert Fatigue in Security Operations Centres** (2024) — *ACM Transactions on Internet Technology* (Association for Computing Machinery).  
   **Task:** SOC alert triage & prioritisation | **Framework:** Human–AI teaming (A2C) to reduce alert fatigue | **Data:** SOC alert streams, analyst feedback, decision workflows | **DOI:** https://doi.org/10.1145/3670009

1. **Adopting a Systemic Design Approach to Cyber Security Incident Response** (2025) — *Proceedings of the New Security Paradigms Workshop (NSPW ’24)* (Association for Computing Machinery).  
   **Task:** Cyber security incident response | **Framework:** Systemic design for sociotechnical CSIRT improvement | **Data:** CSIRT interviews, Gigamap workshop artifacts, qualitative case-study data | **DOI:** https://doi.org/10.1145/3703465.3703471
1. **Exploring the Role of Artificial Intelligence in Enhancing Security Operations: A Systematic Review** (2025) — *ACM Computing Surveys* (Association for Computing Machinery).
   **Task:** security operations (SOC automation) | **Survey:** Systematically review AI use-cases across NIST cybersecurity functions | **Data:** literature corpus of 189 studies on AI for SOCs | **DOI:** [https://doi.org/10.1145/3747587](https://doi.org/10.1145/3747587)
### Trust calibration mechanisms
1. **Human Factors in AI-Driven Cybersecurity: Cognitive Biases and Trust Issues** (2025) — *Digital Threats: Research and Practice* (Association for Computing Machinery).  
   **Task:** SOC decision-making & AI-assisted security operations | **Evaluation:** Analyze cognitive biases and trust in AI-driven cybersecurity tools | **Data:** Analyst interviews, comparative analysis of commercial AI security platforms | **DOI:** https://doi.org/10.1145/3759260
1. **Causality for Trustworthy Artificial Intelligence: Status, Challenges and Perspectives** (2025) — *ACM Computing Surveys* (Association for Computing Machinery).
   **Task:** trustworthy AI | **Survey:** Taxonomize causal frameworks, methods, and security perspectives | **Data:** NA | **DOI:** [https://doi.org/10.1145/3665494](https://doi.org/10.1145/3665494)

### End-to-End Integrated Systems

1. **A Survey on Cyber Resilience: Key Strategies, Research Challenges, and Future Directions** (2024) — *ACM Computing Surveys* (Association for Computing Machinery).  
   **Task:** Cyber resilience engineering & risk management | **Survey:** Synthesize strategies, frameworks, and challenges in cyber resilience | **Data:** Surveyed cyber resilience frameworks, tools, applications, and case studies | **DOI:** https://doi.org/10.1145/3649218
1. **A Survey on Cyber Situation-awareness Systems: Framework, Techniques, and Insights** (2022) — *ACM Computing Surveys* (Association for Computing Machinery).  
   **Task:** Cyber situation awareness & monitoring | **Survey:** Analyze frameworks, techniques, and evaluation of cyber SA systems | **Data:** Cyber SA frameworks, monitoring data sources, analysis techniques | **DOI:** https://doi.org/10.1145/3530809

1. **Exploring the Role of Artificial Intelligence in Enhancing Security Operations: A Systematic Review** (2025) — *ACM Computing Surveys* (Association for Computing Machinery).  
   **Task:** Security operations & SOC automation | **Survey:** Systematically review AI applications across SOC functions | **Data:** Surveyed SOC-focused AI studies, NIST CSF-aligned use cases, datasets and tools | **DOI:** https://doi.org/10.1145/3747587

1. **AI-Driven Cybersecurity Framework for Software Development Based on the ANN–ISM Paradigm** (2025) — *Scientific Reports* (Springer Nature).  
   **Task:** Secure software development & risk assessment | **Framework:** ANN–ISM-based AI-driven cybersecurity framework | **Data:** Software development risk factors, expert assessments, ANN training data | **DOI:** https://doi.org/10.1038/s41598-025-97204-y


1. **Navigating Artificial General Intelligence Development: Societal, Technological, Ethical, and Brain-Inspired Pathways** (2025) — *Scientific Reports* (Springer Nature).  
   **Task:** AI governance & system design | **Survey:** Analyze pathways and challenges toward AGI development | **Data:** Surveyed AGI theories, ethical frameworks, brain-inspired models, socio-technical analyses | **DOI:** https://doi.org/10.1038/s41598-025-92190-7


1. **Mastering Defensive Security: Effective Techniques to Secure Your Windows, Linux, IoT, and Cloud Infrastructure** (2022) — *Book* (Packt Publishing).  
   **Book:** Defensive cybersecurity & infrastructure hardening | **Method:** Practical defensive techniques and security tooling | **Data:** System and network telemetry, malware samples, vulnerability assessment outputs | **URL:** https://ieeexplore.ieee.org/document/10163217


1. **Analyzing and Categorizing Emerging Cybersecurity Regulations** (2025) — *ACM Computing Surveys* (Association for Computing Machinery).  
   **Task:** Cybersecurity compliance & risk management | **Survey:** Analyze and categorize global cybersecurity regulations | **Data:** Surveyed national and regional cybersecurity regulations, regulatory feature taxonomy | **DOI:** https://doi.org/10.1145/3757318

1. **Regulating Information and Network Security: Review and Challenges** (2025) — *ACM Computing Surveys* (Association for Computing Machinery).  
   **Task:** Cybersecurity regulation & governance | **Survey:** Review effectiveness and challenges of security regulations | **Data:** National, international, and industry cybersecurity regulations, empirical impact studies | **DOI:** https://doi.org/10.1145/3711124

1. **Leveraging Data Analytics to Revolutionize Cybersecurity With Machine Learning and Deep Learning** (2025) — *Scientific Reports* (Springer Nature).  
   **Task:** Cybersecurity analytics & threat detection | **Survey:** Analyze ML/DL-driven data analytics for cybersecurity | **Data:** Surveyed security datasets, ML/DL models, analytics pipelines | **DOI:** https://doi.org/10.1038/s41598-025-16932-3

1. **Advanced Persistent Threat Attack Detection Systems: A Review of Approaches, Challenges, and Trends** (2024) — *Digital Threats: Research and Practice* (Association for Computing Machinery).  
   **Task:** APT detection & threat analysis | **Survey:** Review and classify APT detection approaches and challenges | **Data:** Surveyed APT detection systems, threat models, evaluation datasets | **DOI:** https://doi.org/10.1145/3696014

1. **Adversarial Machine Learning in IoT Security: A Comprehensive Survey** (2025) — *ACM Computing Surveys* (Association for Computing Machinery).  
   **Task:** IoT security & intrusion detection robustness | **Survey:** Analyze adversarial ML threats and defenses for IoT IDSs | **Data:** Surveyed AML techniques, IoT IDS datasets, adversarial evaluation practices | **DOI:** https://doi.org/10.1145/3785665
1. **System-level Analysis of Adversarial Attacks and Defenses on Intelligence in O-RAN–Based Cellular Networks** (2024) — *Proceedings of the 17th ACM Conference on Security and Privacy in Wireless and Mobile Networks (WiSec ’24)* (Association for Computing Machinery).  
   **Task:** Adversarial robustness of ML-driven O-RAN components | **Evaluation:** System-level analysis of attacks and distillation-based defenses for xApps | **Data:** O-RAN near-RT RIC data, spectrograms, key performance metrics (KPMs), LTE/5G testbed traces | **DOI:** https://doi.org/10.1145/3643833.3656119

1. **Adversarial Patterns: Building Robust Android Malware Classifiers** (2025) — *ACM Computing Surveys* (Association for Computing Machinery).  
   **Task:** Android malware detection & robustness | **Survey:** Review adversarial attacks and defenses for Android malware classifiers | **Data:** Surveyed Android malware datasets, adversarial examples, ML/DL classifier designs | **DOI:** https://doi.org/10.1145/3717607
1. **Artificial Intelligence for Next Generation Cybersecurity: The AI4CYBER Framework** (2023) — *Proceedings of the 18th International Conference on Availability, Reliability and Security (ARES ’23)* (Association for Computing Machinery).  
   **Task:** Cyber incident response & recovery for critical infrastructure | **Framework:** AI-driven autonomous cybersecurity services across IR lifecycle | **Data:** Incident response workflows, cyber threat intelligence inputs, system telemetry | **DOI:** https://doi.org/10.1145/3600160.3605051

### 7. Math behind the Causal Reasoning 

1. **Decision making under uncertainty** (1996) — *ACM Computing Surveys* (Association for Computing Machinery).
   **Task:** decision making under uncertainty | **Framework:** Discuss probabilistic reasoning for uncertain decisions | **Data:** NA | **DOI:** [https://doi.org/10.1145/234313.234354](https://doi.org/10.1145/234313.234354)

1. **Causal diagrams for empirical research** (1995) — *Biometrika* (Oxford University Press).
   **Task:** causal inference | **Framework:** Identify causal effects via graphical models | **Data:** nonexperimental observational data | **DOI:** [https://doi.org/10.1093/biomet/82.4.669](https://doi.org/10.1093/biomet/82.4.669)

1. **Probabilistic Reasoning in Intelligent Systems: Networks of Plausible Inference** (1988) — *Probabilistic Reasoning in Intelligent Systems: Networks of Plausible Inference* (Morgan Kaufmann Publishers Inc.).
   **Task:** probabilistic reasoning and causal modeling | **Framework:** Formalize belief networks for reasoning under uncertainty | **Data:** NA | **DOI:** [https://doi.org/10.5555/534975](https://doi.org/10.5555/534975)

1. **Causality: Models, Reasoning and Inference (2nd Edition)** (2009) — *Causality: Models, Reasoning and Inference* (Cambridge University Press).
   **Task:** causal inference | **Framework:** Formalize causality, counterfactuals, and structural models | **Data:** NA | **URL:** https://bayes.cs.ucla.edu/BOOK-2K/

1. **The Book of Why: The New Science of Cause and Effect** (2018) — *The Book of Why: The New Science of Cause and Effect* (Basic Books, Inc.).
   **Task:** causal reasoning | **Framework:** Explain modern causality and counterfactual thinking | **Data:** NA | **DOI:** [https://doi.org/10.5555/3238230](https://doi.org/10.5555/3238230)

1. **Axiomatic Effect Propagation in Structural Causal Models** (2024) — *Journal of Machine Learning Research (JMLR)*.  
   **Task:** Causal effect attribution & decomposition | **Framework:** Structural Causal Models (SCMs) on directed acyclic graphs (DAGs) | **Method:** Recursive Shapley Value (RSV), a flow-based causal effect decomposition satisfying four axiomatic properties | **Model Scope:** Linear and non-parametric Structural Equation Models (SEMs) | 
   **DOI:** https://doi.org/10.5555/3722577.3722629
1. **Elements of Causal Inference: Foundations and Learning Algorithms** (2017) — *Elements of Causal Inference: Foundations and Learning Algorithms* (The MIT Press).
   **Task:** causal inference | **Framework:** Foundations and algorithms for learning causal models | **Data:** observational and interventional data | **URL:** https://dl.acm.org/doi/10.5555/3202377

1. **Invariant Models for Causal Transfer Learning** (2018) — *Journal of Machine Learning Research* (JMLR.org).
   **Task:** transfer learning / domain generalization | **Causal:** Learn invariant predictors across environments | **Data:** synthetic datasets, gene deletion data | **DOI:** [https://doi.org/10.48550/arXiv.1507.05333](https://doi.org/10.48550/arXiv.1507.05333)



1. **Domain Adaptation under Structural Causal Models** (2021) — *Journal of Machine Learning Research (JMLR)*.  
   **Task:** Domain adaptation & domain generalization under distribution shift  
   **Framework:** Structural Causal Models (SCMs) and Structural Equation Models (SEMs)  
   **Problem Setting:** Source–target distribution mismatch affecting covariates and/or labels  
   **Method:** CIRM (Conditionally Invariant Representation Method)  
   **Keywords:** Structural causal models, domain adaptation, label shift, invariant prediction, anticausal learning  
   **DOI:** https://doi.org/10.5555/3546258.3546519
1. **Learning a Structural Causal Model for Intuition Reasoning in Conversation** (2024) — *IEEE Transactions on Knowledge and Data Engineering*.  
   **Task:** Utterance-level conversational reasoning  
   **Approach:** Conversation Cognitive Model (CCM) transformed into a Structural Causal Model (SCM)  
   **Method:** Probabilistic SCM with variational inference to model implicit causes  
   **Data:** Synthetic, simulated, and real-world conversation datasets  
   **DOI:** https://doi.org/10.1109/TKDE.2024.3352575

1. **Functional directed acyclic graphs** (2024) — *Journal of Machine Learning Research* (JMLR.org).
   **Task:** causal discovery | **Method:** Estimate DAGs from multivariate functional data | **Data:** multivariate functional data, simulations, time-course proteomic data | **DOI:** [https://doi.org/10.5555/3722577.3722655](https://doi.org/10.5555/3722577.3722655)

1. **Instrumental Variables in Causal Inference and Machine Learning: A Survey** (2025) — *ACM Computing Surveys* (Association for Computing Machinery).
   **Task:** causal inference and machine learning | **Survey:** Review IV methods for unobserved confounding | **Data:** benchmark datasets, reviewed algorithms and applications | **DOI:** [https://doi.org/10.1145/3735969](https://doi.org/10.1145/3735969)

1. **Causality in Bandits: A Survey** (2025) — *ACM Computing Surveys* (Association for Computing Machinery).
   **Task:** causal bandits | **Survey:** Taxonomize and review causal bandit methods | **Data:** NA | **DOI:** [https://doi.org/10.1145/3744917](https://doi.org/10.1145/3744917)

1. **Deep Causal Learning: Representation, Discovery and Inference** (2025) — *ACM Computing Surveys* (Association for Computing Machinery).
   **Task:** causal learning | **Survey:** Review deep learning for causal representation, discovery, inference | **Data:** NA | **DOI:** [https://doi.org/10.1145/3762179](https://doi.org/10.1145/3762179)


### 8. Application of  Causal Inference 

1. **Causal-learn: causal discovery in Python** (2024) — *Journal of Machine Learning Research* (JMLR.org).
   **Task:** causal discovery | **System:** Provide comprehensive Python library for causal discovery | **Data:** observational data | **DOI:** [https://doi.org/10.5555/3722577.3722637](https://doi.org/10.5555/3722577.3722637)

1. **Housing Price Prediction Using AI Agent With Causal Inference for Societal Factor Selection** (2025) — *IEEE Access* (Institute of Electrical and Electronics Engineers).  
   **Task:** Interpretable housing price prediction | **Framework:** AI agent with CPSS ontology + Structural Causal Model (SCM) + XGBoost | **Method:** Causal factor selection via Bayesian networks followed by predictive modeling | **Data:** 23,901 real estate transaction records from four districts in Taipei with multidimensional societal factors | **Results:** MAPE ↓ 5%, RMSE ↓ 11%, R² ↑ 4% (R² ≈ 0.92–0.93 across districts) | **DOI:** https://doi.org/10.1109/ACCESS.2025.3636586
1. **Learning a Structural Causal Model for Intuition Reasoning in Conversation** (2024) — *IEEE Transactions on Knowledge and Data Engineering* (Institute of Electrical and Electronics Engineers).  
   **Task:** Conversational reasoning & natural language understanding | **Framework:** Conversation Cognitive Model (CCM) transformed into a Structural Causal Model (SCM) | **Method:** Probabilistic SCM with variational inference for utterance-level causal reasoning and implicit cause reconstruction | **Data:** Synthetic datasets, simulated datasets with complete cause labels, and real-world conversational datasets | **DOI:** https://doi.org/10.1109/TKDE.2024.3352575
1. **DoWhy-GCM: An Extension of DoWhy for Causal Inference in Graphical Causal Models** (2024) — *Journal of Machine Learning Research (JMLR)*.  
   **Task:** General-purpose causal analysis and diagnosis  
   **Tool:** DoWhy-GCM (Python library)  
   **DOI:** https://doi.org/10.5555/3722577.3722724
1. **Multiparameter Causal Models for the Estimation and Explainability of Wildfire Burned Area** (2025) — *IEEE Journal of Selected Topics in Applied Earth Observations and Remote Sensing*.  
   **Task:** Wildfire burned-area estimation & explainability  
   **Method:** Causal discovery (PCMCI) + do-calculus  
   **Data:** Multiscale climate, atmospheric, and land variables (South Asia time-series)  
   **DOI:** https://doi.org/10.1109/JSTARS.2025.3573263
11. **Joint Causal Inference from Multiple Contexts** (2020) — *Journal of Machine Learning Research (JMLR).*
   **Task:** Causal discovery across heterogeneous environments | **Framework:** Joint Causal Inference (JCI) for unifying observational and interventional data | **Method:** Context-aware causal modeling supporting perfect, imperfect, and stochastic interventions without prior knowledge of targets |  **DOI:** [https://dl.acm.org/doi/10.5555/3455716.3455815](https://dl.acm.org/doi/10.5555/3455716.3455815)

1. **Simplifying Probabilistic Expressions in Causal Inference** (2017) — *Journal of Machine Learning Research (JMLR).*
   **Task:** Causal inference & effect identification | **Method:** Automatic simplification of do-calculus–based causal effect expressions using graphical model structure |  **DOI:** [https://dl.acm.org/doi/10.5555/3122009.3122045](https://dl.acm.org/doi/10.5555/3122009.3122045)

1. **A Survey of Event Causality Identification: Taxonomy, Challenges, Assessment, and Prospects** (2025) — *ACM Computing Surveys* (Association for Computing Machinery).
   **Task:** event causality identification (NLP) | **Survey:** Taxonomize and evaluate ECI models and challenges | **Data:** text corpora, four benchmark ECI datasets | **DOI:** [https://doi.org/10.1145/3756009](https://doi.org/10.1145/3756009)

1. **Introduction to Causal Inference** (2010) — *Journal of Machine Learning Research (JMLR).*
   **Task:** Foundations of causal inference | **Focus:** Graphical causal modeling for reasoning about mechanisms and interventions | **Scope:** Causal discovery from observational and mixed observational–experimental data | **DOI:** [https://dl.acm.org/doi/10.5555/1756006.1859905](https://dl.acm.org/doi/10.5555/1756006.1859905)

1. **Conditions and Assumptions for Constraint-Based Causal Structure Learning** (2022) — *Journal of Machine Learning Research (JMLR).*
   **Task:** Causal discovery & structure learning | **Focus:** Constraint-based learning of causal graphs with latent variables | **Framework:** Structural Causal Models (SCMs) and ancestral graphs | 
     **DOI:** [https://dl.acm.org/doi/10.5555/3586589.3586698](https://dl.acm.org/doi/10.5555/3586589.3586698)

1. **Facilitating Score and Causal Inference Trees for Large Observational Studies** (2012) — *Journal of Machine Learning Research (JMLR).*
   **Task:** Causal effect estimation & heterogeneity analysis | **Method:** Causal Inference Trees (CIT) | **Framework:** Facilitating score capturing confounding and interaction effects | **Data:** Large-scale observational studies (e.g., NSW labor training dataset) | 
     **DOI:** [https://dl.acm.org/doi/10.5555/2503308.2503336](https://dl.acm.org/doi/10.5555/2503308.2503336)

1. **Causal Reasoning with Ancestral Graphs** (2008) — *Journal of Machine Learning Research* (JMLR.org).
   **Task:** causal reasoning | **Causal:** Extend do-calculus to ancestral graphs | **Data:** observational data, ancestral graphs | **DOI:** [https://doi.org/10.5555/1390681.1442780](https://doi.org/10.5555/1390681.1442780)

1. **Model-based causal discovery for zero-Inflated count data** (2023) — *Journal of Machine Learning Research* (JMLR.org).
   **Task:** causal discovery | **Method:** Discover causal DAGs for zero-inflated counts | **Data:** observational zero-inflated count data, synthetic data, single-cell RNA-sequencing | **DOI:** [https://doi.org/10.5555/3648699.3648899](https://doi.org/10.5555/3648699.3648899)
1. **On causality in domain adaptation and semi-supervised learning: an information-theoretic analysis for parametric models** (2024) — *Journal of Machine Learning Research* (JMLR.org).
   **Task:** domain adaptation and semi-supervised learning | **Causal:** Analyze causal vs anti-causal generalization rates | **Data:** labelled source data, unlabelled target data | **DOI:** [https://doi.org/10.5555/3722577.3722838](https://doi.org/10.5555/3722577.3722838)
1. **Instrumental variable value iteration for causal offline reinforcement learning** (2024) — *Journal of Machine Learning Research* (JMLR.org).
   **Task:** offline reinforcement learning | **Method:** Identify confounded dynamics via instrumental variables | **Data:** observational RL trajectories, instrumental variables | **DOI:** [https://doi.org/10.5555/3722577.3722880](https://doi.org/10.5555/3722577.3722880)
1. **Desiderata for representation learning: a causal perspective** (2024) — *Journal of Machine Learning Research* (JMLR.org).
   **Task:** representation learning | **Causal:** Formalize representation desiderata via counterfactuals | **Data:** single observational datasets | **DOI:** [https://doi.org/10.5555/3722577.3722852](https://doi.org/10.5555/3722577.3722852)
1. **Estimating causal structure using conditional DAG models** (2016) — *Journal of Machine Learning Research* (JMLR.org).
   **Task:** causal discovery | **Method:** Estimate causal DAGs using secondary variables | **Data:** joint observational data, simulated data, Cancer Genome Atlas molecular data | **DOI:** [https://doi.org/10.5555/2946645.2946699](https://doi.org/10.5555/2946645.2946699)

1. **A unified experiment design approach for cyclic and acyclic causal models** (2023) — *Journal of Machine Learning Research* (JMLR.org).
   **Task:** causal structure learning | **Method:** Design experiments to identify cyclic and acyclic graphs | **Data:** interventional and observational data from structural causal models | **DOI:** [https://doi.org/10.5555/3648699.3649053](https://doi.org/10.5555/3648699.3649053)

1. **Scalable computation of causal bounds** (2023) — *Journal of Machine Learning Research* (JMLR.org).
   **Task:** causal inference | **Method:** Compute causal bounds via pruned linear programs | **Data:** discrete observational data, causal graphs with unobserved confounders | **DOI:** [https://doi.org/10.5555/3648699.3648936](https://doi.org/10.5555/3648699.3648936)
1. **On efficient adjustment in causal graphs** (2020) — *Journal of Machine Learning Research* (JMLR.org).
   **Task:** causal inference | **Method:** Identify variance-optimal covariate adjustment sets | **Data:** observational data, causal graphs | **DOI:** [https://doi.org/10.5555/3455716.3455962](https://doi.org/10.5555/3455716.3455962)
1. **Causal discovery toolbox: uncovering causal relationships in Python** (2020) — *Journal of Machine Learning Research* (JMLR.org).
   **Task:** causal discovery | **System:** Provide end-to-end causal discovery framework | **Data:** observational data, domain background knowledge | **DOI:** [https://doi.org/10.5555/3455716.3455753](https://doi.org/10.5555/3455716.3455753)

1. **Enhancing identification of causal effects by pruning** (2017) — *Journal of Machine Learning Research* (JMLR.org).
   **Task:** causal inference | **Method:** Prune redundant variables in causal effect identification | **Data:** observational probability distributions, causal graphs | **DOI:** [https://doi.org/10.5555/3122009.3242051](https://doi.org/10.5555/3122009.3242051)

1. **Causal bandits for linear structural equation models** (2023) — *Journal of Machine Learning Research* (JMLR.org).
   **Task:** causal bandits | **Method:** Optimize interventions via linear SEM parameter estimation | **Data:** interventional and observational data from linear SEMs | **DOI:** [https://doi.org/10.5555/3648699.3648996](https://doi.org/10.5555/3648699.3648996)

1. **Python package for causal discovery based on LiNGAM** (2023) — *Journal of Machine Learning Research* (JMLR.org).
   **Task:** causal discovery | **System:** Provide LiNGAM-based causal discovery toolkit | **Data:** observational data, time series data, mixed data, multi-group data | **DOI:** [https://doi.org/10.5555/3648699.3648713](https://doi.org/10.5555/3648699.3648713)
1. **Towards integrative causal analysis of heterogeneous data sets and studies** (2012) — *Journal of Machine Learning Research* (JMLR.org).
   **Task:** integrative causal analysis | **Framework:** Integrate heterogeneous datasets via causal models | **Data:** multiple heterogeneous datasets with overlapping variables | **DOI:** [https://doi.org/10.5555/2503308.2343683](https://doi.org/10.5555/2503308.2343683)


### 9. LLM with Causal Reasoning  

1. **Attention Is All You Need** (2017) — *Advances in Neural Information Processing Systems (NeurIPS 2017)* (Curran Associates Inc.).
   **Task:** sequence transduction / representation learning | **Method:** Introduce Transformer architecture based on self-attention | **Data:** machine translation corpora (WMT 2014 En–De, En–Fr), parsing datasets | **DOI:** [https://doi.org/10.48550/arXiv.1706.03762](https://doi.org/10.48550/arXiv.1706.03762)
1. **Causality for Machine Learning** (2019) — *Probabilistic and Causal Inference: The Works of Judea Pearl* (Association for Computing Machinery).
   **Task:** causal learning | **Survey:** Connect causal inference with machine learning challenges | **Data:** NA | **DOI:** [https://doi.org/10.48550/arXiv.1911.10500](https://doi.org/10.48550/arXiv.1911.10500)

1. **Towards Causal Representation Learning** (2021) — *Proceedings of the IEEE (Special Issue: Advances in Machine Learning and Deep Neural Networks)* (Institute of Electrical and Electronics Engineers).
   **Task:** causal representation learning | **Survey:** Link causal inference with representation learning and generalization | **Data:** NA | **DOI:** [https://doi.org/10.48550/arXiv.2102.11107](https://doi.org/10.48550/arXiv.2102.11107)


1. **From Statistical to Causal Learning** (2022) — *Proceedings of the International Congress of Mathematicians 2022* (EMS Press).
   **Task:** causal learning | **Survey:** Motivate shift from statistical to causal AI | **Data:** NA | **DOI:** [https://doi.org/10.48550/arXiv.2204.00607](https://doi.org/10.48550/arXiv.2204.00607)

1. **Can Large Language Models Infer Causation from Correlation?** (2023) — *arXiv (cs.CL)* (arXiv.org).
   **Task:** causal reasoning evaluation | **Evaluation:** Assess LLM ability to infer causation beyond correlation | **Data:** synthetic causal datasets, controlled text-based causal scenarios | **DOI:** [https://doi.org/10.48550/arXiv.2306.05836](https://doi.org/10.48550/arXiv.2306.05836)

1. **\card: Evaluating Causal Reasoning Capabilities of Large Language Models** (2024) — *arXiv (cs.CL)* (arXiv.org).
   **Task:** causal reasoning evaluation | **Evaluation:** Benchmark and assess causal reasoning abilities of LLMs | **Data:** controlled causal reasoning benchmarks and synthetic scenarios | **DOI:** [https://doi.org/10.48550/arXiv.2412.17970](https://doi.org/10.48550/arXiv.2412.17970)

1. **Failure Modes of LLMs for Causal Reasoning on Narratives** (2025) — *arXiv (cs.LG)* (arXiv.org).
   **Task:** causal reasoning on narratives | **Evaluation:** Analyze systematic failure modes of LLM causal reasoning | **Data:** narrative-based causal reasoning datasets, synthetic story scenarios | **DOI:** [https://doi.org/10.48550/arXiv.2410.23884](https://doi.org/10.48550/arXiv.2410.23884)

1. **LLMs for Generating and Evaluating Counterfactuals: A Comprehensive Study** (2024) — *arXiv (cs.CL)* (arXiv.org).
   **Task:** counterfactual reasoning with LLMs | **Evaluation:** Generate and assess counterfactual explanations using LLMs | **Data:** counterfactual reasoning benchmarks, synthetic and text-based scenarios | **DOI:** [https://doi.org/10.48550/arXiv.2405.00722](https://doi.org/10.48550/arXiv.2405.00722)

1. **Prompting Large Language Models for Counterfactual Generation: An Empirical Study** (2024) — *arXiv (cs.CL)* (arXiv.org).
   **Task:** counterfactual generation | **Evaluation:** Empirically assess prompting strategies for counterfactuals | **Data:** text-based counterfactual benchmarks and synthetic scenarios | **DOI:** [https://doi.org/10.48550/arXiv.2305.14791](https://doi.org/10.48550/arXiv.2305.14791)

1. **Locating and Editing Factual Associations in GPT** (2022) — *Advances in Neural Information Processing Systems (NeurIPS 2022)* (Curran Associates Inc.).
   **Task:** causal analysis of language models | **Method:** Identify and causally edit factual associations in Transformers | **Data:** zsRE dataset, counterfactual factual assertion dataset | **DOI:** [https://doi.org/10.48550/arXiv.2202.05262](https://doi.org/10.48550/arXiv.2202.05262)

1. **Causal Abstractions of Neural Networks** (2021) — *Advances in Neural Information Processing Systems (NeurIPS 2021)* (Curran Associates Inc.).
   **Task:** neural network interpretability | **Method:** Validate causal abstractions via interchange interventions | **Data:** MQNLI dataset, neural representations from BERT-based models | **DOI:** [https://doi.org/10.48550/arXiv.2106.02997](https://doi.org/10.48550/arXiv.2106.02997)

1. **Measuring Causal Effects of Data Statistics on Language Model’s “Factual” Predictions** (2023) — *arXiv (cs.CL)* (arXiv.org).
   **Task:** causal analysis of language models | **Causal:** Estimate causal effects of data statistics on factual predictions | **Data:** pretrained language models, observational training data statistics (e.g., co-occurrence counts) | **DOI:** [https://doi.org/10.48550/arXiv.2207.14251](https://doi.org/10.48550/arXiv.2207.14251)
 
1. **Chain-of-Thought Prompting Elicits Reasoning in Large Language Models** (2022) — *Advances in Neural Information Processing Systems (NeurIPS 2022)* (Curran Associates Inc.).
   **Task:** reasoning with large language models | **Method:** Elicit multi-step reasoning via chain-of-thought prompting | **Data:** arithmetic, commonsense, and symbolic reasoning benchmarks (e.g., GSM8K) | **DOI:** [https://doi.org/10.48550/arXiv.2201.11903](https://doi.org/10.48550/arXiv.2201.11903)


1. **Tree of Thoughts: Deliberate Problem Solving with Large Language Models** (2023) — *Advances in Neural Information Processing Systems (NeurIPS 2023)* (Curran Associates Inc.).
   **Task:** reasoning and planning with LLMs | **Method:** Enable deliberate multi-path reasoning via tree-structured thought exploration | **Data:** Game of 24, creative writing tasks, mini crossword puzzles | **DOI:** [https://doi.org/10.48550/arXiv.2305.10601](https://doi.org/10.48550/arXiv.2305.10601)

1. **Self-Consistency Improves Chain of Thought Reasoning in Language Models** (2023) — *International Conference on Learning Representations (ICLR 2023)* (OpenReview).
   **Task:** reasoning with large language models | **Method:** Improve chain-of-thought via self-consistent sampling | **Data:** arithmetic and commonsense reasoning benchmarks (GSM8K, SVAMP, AQuA, StrategyQA, ARC-Challenge) | **DOI:** [https://doi.org/10.48550/arXiv.2203.11171](https://doi.org/10.48550/arXiv.2203.11171)
1. **Language Models as Causal Effect Generators** (2025) — *arXiv (cs.CL)* (arXiv.org).
   **Task:** causal effect estimation with LLMs | **Method:** Use language models to generate causal effect estimates | **Data:** synthetic causal tasks, text-based causal scenarios | **DOI:** [https://doi.org/10.48550/arXiv.2411.08019](https://doi.org/10.48550/arXiv.2411.08019)

1. **Causal Reflection with Language Models** (2025) — *arXiv (cs.LG)* (arXiv.org).
   **Task:** causal reasoning with language models | **Method:** Enable causal reflection and self-analysis in LLMs | **Data:** NA | **DOI:** [https://doi.org/10.48550/arXiv.2508.04495](https://doi.org/10.48550/arXiv.2508.04495)
1. **Large Language Models Are Neurosymbolic Reasoners** (2024) — *arXiv (cs.CL)* (arXiv.org).
   **Task:** reasoning with large language models | **Framework:** Characterize LLMs as neurosymbolic reasoners | **Data:** reasoning benchmarks and synthetic symbolic tasks | **DOI:** [https://doi.org/10.48550/arXiv.2401.09334](https://doi.org/10.48550/arXiv.2401.09334)
1. **CausalTrace: A Neurosymbolic Causal Analysis Agent for Smart Manufacturing** (2025) — *arXiv (cs.AI)* (arXiv.org).
   **Task:** causal analysis and root-cause diagnosis | **System:** Neurosymbolic agent for causal tracing and reasoning | **Data:** manufacturing process data, sensor telemetry, event logs | **DOI:** [https://doi.org/10.48550/arXiv.2510.12033](https://doi.org/10.48550/arXiv.2510.12033)
1. **CLEVRER: CoLlision Events for Video REpresentation and Reasoning** (2020) — *International Conference on Learning Representations (ICLR 2020)* (OpenReview).
   **Task:** causal and temporal reasoning from video | **Dataset:** Benchmark causal reasoning (explanatory, predictive, counterfactual) | **Data:** synthetic physics-based videos with collision events | **DOI:** [https://doi.org/10.48550/arXiv.1910.01442](https://doi.org/10.48550/arXiv.1910.01442)

1. **Unveiling Causal Reasoning in Large Language Models: Reality or Mirage?** (2024) — *Advances in Neural Information Processing Systems (NeurIPS 2024)* (Curran Associates Inc.).
   **Task:** causal reasoning evaluation | **Evaluation:** Distinguish shallow vs genuine causal reasoning in LLMs | **Data:** CausalProbe-2024 benchmark, counterfactual and fresh causal Q&A | **DOI:** [https://doi.org/10.48550/arXiv.2506.21215](https://doi.org/10.48550/arXiv.2506.21215)

1. **Compositional Causal Reasoning Evaluation in Language Models** (2025) — *International Conference on Machine Learning (ICML 2025)* (International Machine Learning Society).
   **Task:** causal reasoning evaluation | **Evaluation:** Measure compositional causal reasoning in language models | **Data:** synthetic causal math word problems, causal graphs evaluating ATE and PNS | **DOI:** [https://doi.org/10.48550/arXiv.2503.04556](https://doi.org/10.48550/arXiv.2503.04556)

1. **On the Dangers of Stochastic Parrots: Can Language Models Be Too Big?** (2021) — *Proceedings of the ACM Conference on Fairness, Accountability, and Transparency (FAccT 2021)* (Association for Computing Machinery).
   **Task:** responsible AI and language models | **Survey:** Critically assess risks, limitations, and harms of large language models | **Data:** NA | **DOI:** [https://doi.org/10.1145/3442188.3445922](https://doi.org/10.1145/3442188.3445922)

1. **CausalBench: A Comprehensive Benchmark for Causal Learning Capability of LLMs** (2024) — *arXiv (cs.LG)* (arXiv.org).
   **Task:** causal learning and discovery | **Benchmark:** Evaluate correlation, skeleton, and causal direction learning | **Data:** synthetic and community-standard causal graphs (small to large-scale, >50 nodes) | **DOI:** [https://doi.org/10.48550/arXiv.2404.06349](https://doi.org/10.48550/arXiv.2404.06349)


1. **CLadder: Assessing Causal Reasoning in Language Models** (2023) — *Advances in Neural Information Processing Systems (NeurIPS 2023)* (Curran Associates, Inc.).
   **Task:** causal reasoning evaluation | **Benchmark:** Evaluate associational, interventional, and counterfactual reasoning in LLMs | **Data:** CLadder dataset (≈10K samples derived from causal graphs and oracle causal inference engine) | **DOI:** [https://doi.org/10.48550/arXiv.2312.04350](https://doi.org/10.48550/arXiv.2312.04350)


1. **Solving a Million-Step LLM Task with Zero Errors** (2025) — *arXiv (cs.AI)* (arXiv.org).
   **Task:** long-horizon reasoning and planning | **System:** Massively decomposed multi-agent process with error correction | **Data:** synthetic long-horizon planning benchmarks (e.g., Towers of Hanoi–style tasks) | **DOI:** [https://doi.org/10.48550/arXiv.2511.09030](https://doi.org/10.48550/arXiv.2511.09030)


1. **Agent0: Unleashing Self-Evolving Agents from Zero Data via Tool-Integrated Reasoning** (2025) — *arXiv (cs.LG)* (arXiv.org).
   **Task:** agentic reasoning and curriculum learning | **System:** Self-evolving multi-agent framework with tool-integrated reasoning | **Data:** zero external data; self-generated curricula and tool-based tasks | **DOI:** [https://doi.org/10.48550/arXiv.2511.16043](https://doi.org/10.48550/arXiv.2511.16043)

1. **Retrieval-Augmented Generation for Knowledge-Intensive NLP Tasks** (2020) — *Advances in Neural Information Processing Systems (NeurIPS 2020)* (Curran Associates Inc.).
   **Task:** knowledge-intensive NLP | **Method:** Combine parametric LMs with non-parametric retrieval for generation | **Data:** Wikipedia corpus, open-domain QA and knowledge-intensive NLP benchmarks | **DOI:** [https://doi.org/10.48550/arXiv.2005.11401](https://doi.org/10.48550/arXiv.2005.11401)

1. **Artificial Hivemind: The Open-Ended Homogeneity of Language Models (and Beyond)** (2025) — *Advances in Neural Information Processing Systems (NeurIPS 2025), Datasets and Benchmarks Track* (Curran Associates Inc.).
   **Task:** analysis of LLM behavior and diversity | **Benchmark:** Quantify intra- and inter-model homogeneity in open-ended generation | **Data:** Infinity-Chat dataset (26K open-ended prompts, 31,250 human annotations) | **DOI:** [https://doi.org/10.48550/arXiv.2510.22954](https://doi.org/10.48550/arXiv.2510.22954)


1. **Causality Analysis for Evaluating the Security of Large Language Models** (2023) — *arXiv (cs.AI)* (arXiv.org).
   **Task:** LLM security evaluation | **Causal:** Analyze causal effects at token, layer, and neuron levels to expose vulnerabilities | **Data:** open-source LLMs (Llama2, Vicuna), Trojan Detection Competition 2023 red-teaming prompts | **DOI:** [https://doi.org/10.48550/arXiv.2312.07876](https://doi.org/10.48550/arXiv.2312.07876)

1. **CausalChat: Interactive Causal Model Development and Refinement Using Large Language Models** (2025) — *IEEE Transactions on Visualization and Computer Graphics* (Institute of Electrical and Electronics Engineers).
   **Task:** causal modeling and analysis | **System:** Interactive visual analytics system using LLMs for causal model development | **Data:** user-provided datasets, causal graphs, interactive visual artifacts | **DOI:** [https://doi.org/10.1109/TVCG.2025.3602448](https://doi.org/10.1109/TVCG.2025.3602448)

1. **Privacy Preserving Prompt Engineering: A Survey** (2025) — *ACM Computing Surveys* (Association for Computing Machinery).
   **Task:** privacy-preserving prompting and ICL | **Survey:** Systematically review privacy risks and mitigation methods in prompting/ICL | **Data:** surveyed literature, mitigation techniques, and public resources | **DOI:** [https://doi.org/10.1145/3729219](https://doi.org/10.1145/3729219)

1. **Large Language Models Meet Causal Inference: Semantic-Rich Dual Propensity Score for Sequential Recommendation** (2025) — *IEEE Transactions on Knowledge and Data Engineering* (Institute of Electrical and Electronics Engineers).
   **Task:** sequential recommendation (debiasing) | **Method:** LLM-enhanced dual propensity score estimation to mitigate exposure bias | **Data:** user–item interaction sequences with textual semantics and temporal signals | **DOI:** [https://doi.org/10.1109/TKDE.2025.3606149](https://doi.org/10.1109/TKDE.2025.3606149)

1. **CausalMedLM: Causal inference-augmented LLMs for high-accuracy disease prediction** (2025) — *Knowledge-Based Systems* (Elsevier).
   **Task:** medical diagnosis / disease prediction | **Method:** Augment LLMs with causal inference to improve prediction accuracy | **Data:** electronic health records and clinical features for disease prediction | **DOI:** [https://doi.org/10.1016/j.knosys.2025.115121](https://doi.org/10.1016/j.knosys.2025.115121)

1. **ALCM: Autonomous LLM-Augmented Causal Discovery Framework** (2024) — *arXiv (cs.LG)* (arXiv.org).
   **Task:** causal discovery | **Framework:** Use LLMs to autonomously guide causal structure learning pipelines | **Data:** observational datasets for causal graph discovery | **DOI:** [https://doi.org/10.48550/arXiv.2405.01744](https://doi.org/10.48550/arXiv.2405.01744)
1. **CarICL: Mitigating causal hallucinations to enhance event causality identification** (2025) — *Information Processing & Management* (Elsevier).
   **Task:** event causality identification (NLP) | **Method:** In-context learning framework to reduce causal hallucinations in LLM-based ECI | **Data:** event causality datasets for sentence-/document-level causality | **DOI:** [https://doi.org/10.1016/j.ipm.2025.104500](https://doi.org/10.1016/j.ipm.2025.104500)


1. **Causal relationship extraction from biomedical text using deep neural models: A comprehensive survey** (2021) — *Journal of Biomedical Informatics* (Elsevier).
   **Task:** biomedical causal relation extraction | **Survey:** Review deep neural approaches for extracting causal relations from biomedical text | **Data:** biomedical literature corpora and annotated causal relation datasets | **DOI:** [https://doi.org/10.1016/j.jbi.2021.103820](https://doi.org/10.1016/j.jbi.2021.103820)
