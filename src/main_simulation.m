%% =========================================================
%  MAIN SIMULATION SCRIPT
%  Project : Next-Generation Public Wi-Fi Security Using
%            SDRN-Based Early Attack Detection
%  IEEE Academic Simulation â€“ MATLAB Only (No Hardware)
%  =========================================================
%  Run this file to execute the full simulation pipeline.
%  All helper functions are in separate .m files.
%  =========================================================

clc; clear; close all;
rng(42);  % Reproducible results

fprintf('==============================================\n');
fprintf(' SDRN-Based Wi-Fi Attack Detection Simulation\n');
fprintf('==============================================\n\n');

%% â”€â”€ STEP 1 : Network Topology Setup â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
fprintf('[1/5] Initialising network topology...\n');
net = setup_network();
fprintf('      Legitimate APs : %d | Clients : %d | Attacker nodes : %d\n',...
    net.numLegitAPs, net.numClients, net.numAttackers);

%% â”€â”€ STEP 2 : Simulate Traffic (Normal + Attack Phases) â”€â”€
fprintf('[2/5] Simulating traffic timeline...\n');
sim = simulate_traffic(net);

%% â”€â”€ STEP 3 : Physical-Layer Beacon Fingerprinting â”€â”€â”€â”€â”€â”€â”€
fprintf('[3/5] Running Stage-1 â€“ Beacon Fingerprinting...\n');
beaconResult = detect_rogue_ap(sim, net);

%% â”€â”€ STEP 4 : ARP Analysis (Stage-2 Detection) â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
fprintf('[4/5] Running Stage-2 â€“ ARP / IPâ€“MAC Conflict Analysis...\n');
arpResult = detect_arp_attack(sim, net);

%% â”€â”€ STEP 5 : Fuse Results & Plot â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
fprintf('[5/5] Fusing results and generating plots...\n');
fusedResult = fuse_and_evaluate(beaconResult, arpResult, sim);
generate_plots(sim, beaconResult, arpResult, fusedResult, net);

fprintf('\n[Done] All plots saved. Simulation complete.\n');
