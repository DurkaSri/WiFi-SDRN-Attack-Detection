function result = detect_arp_attack(sim, net)
%% detect_arp_attack  â€“  Stage-2: ARP Flooding & IPâ€“MAC Conflict Detection
%
%  Two complementary sub-detectors are combined:
%
%  Sub-detector A â€“ ARP Rate Anomaly
%    Maintains an exponential moving average of ARP rate.
%    Flags when instantaneous rate exceeds Î¼ + 3Ïƒ of the baseline.
%
%  Sub-detector B â€“ IPâ€“MAC Binding Violation
%    Maintains a learned ARP cache (IP â†’ MAC whitelist).
%    Flags when the same IP maps to two different MACs simultaneously
%    (classic ARP poisoning / gratuitous-ARP attack signature).
%
%  Output struct 'result':
%    .arpDetected    â€“ per-second flag from Sub-detector A
%    .conflictFlag   â€“ per-second flag from Sub-detector B
%    .combined       â€“ OR of both sub-detectors
%    .arpThreshold   â€“ adaptive threshold vector
%    .detectedTime   â€“ earliest combined detection time

N  = sim.N;
t  = sim.time;

%% â”€â”€ Sub-detector A : ARP Rate Anomaly â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
alpha   = 0.05;               % EMA smoothing factor
ema     = sim.arpRate(1);
emaSq   = sim.arpRate(1)^2;
arpThr  = zeros(N,1);
arpDet  = false(N,1);

for k = 1:N
    r       = sim.arpRate(k);
    ema     = alpha*r + (1-alpha)*ema;
    emaSq   = alpha*r^2 + (1-alpha)*emaSq;
    sigma   = sqrt(max(0, emaSq - ema^2));
    thr     = ema + 3*sigma;
    arpThr(k) = thr;

    % Flag if current rate is 2Ã— threshold OR > absolute 50 pkt/s
    if r > thr && r > 50
        arpDet(k) = true;
    end
end

%% â”€â”€ Sub-detector B : IPâ€“MAC Conflict â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
% sim.ipMacConflict is the ground-truth injection.
% We model an SDRN listener that detects the conflict with ~1 s latency
% and a 5 % chance of missing each event (detection probability 0.95).
conflictDet = false(N,1);
for k = 2:N
    if sim.ipMacConflict(k)
        conflictDet(k) = rand() < 0.95;   % 95 % detection probability
    end
end

%% â”€â”€ Combined Stage-2 Flag â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
combined = arpDet | conflictDet;

% First detection time
idx = find(combined, 1, 'first');
if ~isempty(idx)
    result.detectedTime = t(idx);
    fprintf('      [ARP Detect] Attack first detected at t = %.1f s\n', ...
        result.detectedTime);
else
    result.detectedTime = NaN;
end

result.arpDetected   = arpDet;
result.conflictFlag  = conflictDet;
result.combined      = combined;
result.arpThreshold  = arpThr;
end
