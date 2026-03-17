from flask import Flask, render_template, jsonify, send_file
import csv
import os
import json

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
PROJECT_ROOT = os.path.dirname(BASE_DIR)
CSV_PATH = os.path.join(PROJECT_ROOT, "metrics", "goose_metrics.csv")

app = Flask(__name__, static_folder="static", template_folder="templates")

def get_aggregated_metrics():
    if not os.path.exists(CSV_PATH):
        return None, []

    with open(CSV_PATH, newline='') as cf:
        reader = list(csv.DictReader(cf))

    if not reader:
        return None, []

    last_algo = reader[-1]['algo']

    pub_crypto_times, sub_crypto_times, net_transit_times = [], [], []
    pub_throughput, sub_throughput = [], []
    overhead = 0
    
    pub_details_raw = {}
    sub_details_raw = {}

    chart_dict = {}

    for r in reader:
        if r['algo'] != last_algo:
            continue

        try:
            idx = int(r['msg_index'])
        except ValueError:
            continue

        if idx not in chart_dict:
            chart_dict[idx] = {"msg_index": idx, "pub_details": {}, "sub_details": {}}

        try:
            details = {}
            if 'detailed_metrics' in r and r['detailed_metrics']:
                details = json.loads(r['detailed_metrics'])

            if r['direction'] == 'publisher':
                c_ms = float(r['crypto_ms'])
                pub_crypto_times.append(c_ms)
                pub_throughput.append(float(r['throughput_mbps']))
                if r['overhead_bytes']: overhead = int(r['overhead_bytes'])
                
                chart_dict[idx]['pub_crypto_ms'] = c_ms
                
                for k, v in details.items():
                    if k != "pub_total_crypto_ms":
                        if k not in pub_details_raw: pub_details_raw[k] = []
                        pub_details_raw[k].append(v)
                        chart_dict[idx]['pub_details'][k] = v

            elif r['direction'] == 'subscriber':
                c_ms = float(r['crypto_ms'])
                n_ms = float(r['net_transit_ms'])
                sub_crypto_times.append(c_ms)
                net_transit_times.append(n_ms)
                sub_throughput.append(float(r['throughput_mbps']))
                
                chart_dict[idx]['sub_crypto_ms'] = c_ms
                chart_dict[idx]['net_transit_ms'] = n_ms

                for k, v in details.items():
                    if k != "sub_total_crypto_ms":
                        if k not in sub_details_raw: sub_details_raw[k] = []
                        sub_details_raw[k].append(v)
                        chart_dict[idx]['sub_details'][k] = v

        except Exception:
            continue

    def safe_avg(lst):
        return sum(lst) / len(lst) if lst else 0.0

    # Calculate Total E2E Times for each message index
    e2e_times = []
    for idx, data in chart_dict.items():
        if 'pub_crypto_ms' in data and 'sub_crypto_ms' in data and 'net_transit_ms' in data:
            e2e = data['pub_crypto_ms'] + data['net_transit_ms'] + data['sub_crypto_ms']
            data['e2e_time_ms'] = round(e2e, 4)
            e2e_times.append(e2e)
        else:
            data['e2e_time_ms'] = 0.0

    pub_detailed_avgs = {k.replace('_', ' ').title(): round(safe_avg(v), 5) for k, v in pub_details_raw.items()}
    sub_detailed_avgs = {k.replace('_', ' ').title(): round(safe_avg(v), 5) for k, v in sub_details_raw.items()}

    stats = {
        "algo": last_algo.upper(),
        "pub_avg_crypto_ms": round(safe_avg(pub_crypto_times), 4),
        "pub_avg_throughput": round(safe_avg(pub_throughput), 2),
        "pub_detailed_avgs": pub_detailed_avgs,
        "overhead_bytes": overhead,
        "sub_avg_net_ms": round(safe_avg(net_transit_times), 4),
        "sub_avg_crypto_ms": round(safe_avg(sub_crypto_times), 4),
        "sub_avg_throughput": round(safe_avg(sub_throughput), 2),
        "sub_detailed_avgs": sub_detailed_avgs,
        "avg_e2e_ms": round(safe_avg(e2e_times), 4),  # <--- NEW E2E METRIC
        "total_packets_analyzed": len(sub_crypto_times)
    }

    chart_data = [chart_dict[k] for k in sorted(chart_dict.keys())]
    return stats, chart_data

@app.route("/")
def index():
    stats, _ = get_aggregated_metrics()
    return render_template("index.html", stats=stats)

@app.route("/api/metrics")
def api_metrics():
    _, chart_data = get_aggregated_metrics()
    return jsonify({"chart": chart_data})

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000, debug=True)
