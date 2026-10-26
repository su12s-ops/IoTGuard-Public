/* 由 _work/port_to_new_frontend.py 从 showcase/assets/engine.js 转换；逻辑逐分支对齐 backend/app/services/openwrt_intel.py */
/* ───────────────────────────────────────────────────────────────────────────
   设备端判决引擎（浏览器复刻）
   逐函数对照仓库真实实现：
     backend/app/services/openwrt_intel.py : parse_range / normalize_components /
       normalize_advisory / series_of / _release_tuple / evaluate_candidate
     backend/app/services/iot_official.py  : version_in_range
   复刻原则：分支顺序、返回码、confidence 与原文一一对应；不"优化"、不补默认。
   自检：app.js 会把本引擎的结果与服务端参照结果逐条比对，不一致就红显。
   ─────────────────────────────────────────────────────────────────────────── */

  var BRANCH_SCOPES = ["main", "master", "snapshot", "snapshots"];
  var REPO_LEVEL_NAMES = ["openwrt"];
  var RANGE_RE = /^\s*(<=|>=|<|>|≤|≥|=)?\s*v?(\d+\.\d+(?:\.\d+)?)\s*(?:\(([^)]*)\))?\s*$/;
  var COMMIT_RE = /commit\s+[0-9a-f]{7,40}/i;
  var COMMIT_HEX_RE = /[0-9a-f]{7,40}/;
  var SUMMARY_PREFIX_RE = /^\s*([A-Za-z0-9][A-Za-z0-9._+-]{0,30})\s*:/;
  var SUMMARY_FIRST_RE = /^[A-Za-z0-9][A-Za-z0-9._+-]{0,15}$/;
  var FIX_STATEMENT_RE = /([^\n]*\bfixed in OpenWrt (\d+\.\d+(?:\.\d+)?)[^\n]*)/i;
  var COVERS_LATER_RE = /and later|snapshots? builds/i;
  var PROVENANCE = "openwrt_ghsa_normalized";

  function isBranchScope(value) {
    return BRANCH_SCOPES.indexOf(String(value || "").toLowerCase()) !== -1;
  }

  // openwrt_intel._release_tuple
  function releaseTuple(text) {
    var m = /^v?(\d+)\.(\d+)(?:\.(\d+))?$/.exec(String(text == null ? "" : text).trim());
    if (!m) return null;
    return [parseInt(m[1], 10), parseInt(m[2], 10), m[3] === undefined ? 0 : parseInt(m[3], 10)];
  }

  // openwrt_intel.series_of
  function seriesOf(version) {
    var parsed = releaseTuple(version || "");
    if (parsed === null) return "";
    return parsed[0] + "." + parsed[1];
  }

  function cmpTuple(a, b) {
    for (var i = 0; i < 3; i += 1) {
      if (a[i] !== b[i]) return a[i] < b[i] ? -1 : 1;
    }
    return 0;
  }

  // openwrt_intel.parse_range
  function parseRange(expression) {
    var raw = String(expression == null ? "" : expression).trim();
    if (!raw) return { scope: "unknown", raw: raw };
    if (isBranchScope(raw)) return { scope: "branch", branch: raw.toLowerCase(), raw: raw };
    var commitMatch = COMMIT_RE.exec(raw);
    if (commitMatch) {
      var hex = COMMIT_HEX_RE.exec(commitMatch[0]);
      return { scope: "commit", commit: hex ? hex[0] : "", raw: raw };
    }
    var m = RANGE_RE.exec(raw);
    if (m) {
      var rawOp = m[1] || "=";
      var op = rawOp === "≤" ? "<=" : rawOp === "≥" ? ">=" : rawOp;
      return {
        scope: "release",
        op: op,
        version: m[2],
        annotation: (m[3] || "").trim() || null,
        raw: raw,
      };
    }
    return { scope: "unknown", raw: raw };
  }

  // openwrt_intel.normalize_components —— 返回 [{component, source}]
  function normalizeComponents(payload) {
    var resolved = [];
    var seen = {};
    var summary = payload.summary || "";
    var entries = payload.vulnerabilities || [];
    for (var i = 0; i < entries.length; i += 1) {
      var pkg = entries[i].package || {};
      var rawName = String(pkg.name || "").trim();
      if (!rawName) continue;
      var cleaned = rawName.replace(/\s*\([^)]*\)\s*$/, "").trim();
      var source = "package_field:" + rawName;
      if (REPO_LEVEL_NAMES.indexOf(cleaned.toLowerCase()) !== -1) {
        var prefix = SUMMARY_PREFIX_RE.exec(summary);
        if (prefix) {
          cleaned = prefix[1];
          source = "repo_level_summary_prefix:" + summary.slice(0, 80);
        } else {
          var first = summary.split(/\s+/)[0] || "";
          if (SUMMARY_FIRST_RE.test(first)) {
            cleaned = first;
            source = "repo_level_summary_first_token:" + summary.slice(0, 80);
          } else {
            source = "repo_level_unresolved:" + rawName;
          }
        }
      }
      var component = cleaned.toLowerCase();
      var parts = component.split("/");
      for (var p = 0; p < parts.length; p += 1) {
        var part = parts[p].trim();
        if (part && !seen[part]) {
          seen[part] = true;
          resolved.push({ component: part, source: source });
        }
      }
    }
    return resolved;
  }

  // openwrt_intel._fix_statement
  function fixStatement(description) {
    var m = FIX_STATEMENT_RE.exec(description || "");
    if (!m) return null;
    var text = m[1].trim();
    return {
      text: text.slice(0, 400),
      fixed: m[2],
      covers_later_releases: COVERS_LATER_RE.test(text),
    };
  }

  // openwrt_intel.normalize_advisory
  function normalizeAdvisory(payload) {
    var ghsaId = payload.ghsa_id || "";
    var cveId = payload.cve_id || "";
    var htmlUrl = payload.html_url || "";
    var statement = fixStatement(payload.description || "");
    var records = [];
    var components = normalizeComponents(payload);
    var entries = payload.vulnerabilities || [];
    for (var c = 0; c < components.length; c += 1) {
      for (var e = 0; e < entries.length; e += 1) {
        var entry = entries[e];
        var rawRange = String(entry.vulnerable_version_range || "").trim();
        var parsed = parseRange(rawRange);
        var patched = entry.first_patched_version || "";
        var note = {
          provenance: PROVENANCE,
          ghsa_id: ghsaId,
          cve_id: cveId,
          source_url: htmlUrl,
          official_range: rawRange,
          scope: parsed.scope,
          component_source: components[c].source,
          official_summary: (payload.summary || "").slice(0, 200),
          fix_statement: statement,
        };
        var record = {
          cve_id: cveId,
          package_name: components[c].component,
          release: "",
          affected_versions: [],
          fixed_versions: [],
          source_url: htmlUrl,
          notes: note,
        };
        if (parsed.scope === "release") {
          var boundary = releaseTuple(parsed.version);
          if (boundary === null) {
            note.scope = "unknown";
            record.affected_versions = [rawRange];
            records.push(record);
            continue;
          }
          record.release = boundary[0] + "." + boundary[1];
          record.affected_versions = [parsed.op + " " + parsed.version];
          if (patched) {
            record.fixed_versions = [String(patched)];
            note.fixed_note = "官方 first_patched_version。";
          } else if (parsed.op === "<") {
            record.fixed_versions = [parsed.version];
            note.fixed_note = "边界蕴含：< X 表示 X 起不在官方受影响范围；公告未显式给出修复版本号。";
          }
          if (parsed.annotation) note.annotation = parsed.annotation;
          if (note.fixed_note === undefined) note.fixed_note = "";
          records.push(record);
        } else if (parsed.scope === "branch") {
          note.branch = parsed.branch;
          record.release = parsed.branch;
          record.affected_versions = [rawRange];
          records.push(record);
        } else {
          note.commit = parsed.commit || "";
          record.affected_versions = [rawRange];
          records.push(record);
        }
      }
    }
    return records;
  }

  // iot_official.version_in_range —— 仅接受严格三段版本号
  function versionInRange(version, expression) {
    function parse(value) {
      var m = /^v?(\d+)\.(\d+)\.(\d+)$/.exec(String(value || "").trim());
      return m ? [parseInt(m[1], 10), parseInt(m[2], 10), parseInt(m[3], 10)] : null;
    }
    var current = parse(version);
    if (current === null || !expression) return null;
    if (String(expression).trim() === "*") return true;
    var terms = String(expression).split(",");
    var results = [];
    for (var i = 0; i < terms.length; i += 1) {
      var m = /^\s*(>=|<=|>|<|=)?\s*(v?\d+\.\d+\.\d+)\s*$/.exec(terms[i]);
      if (!m) return null;
      var target = parse(m[2]);
      var delta = cmpTuple(current, target);
      var op = m[1] || "=";
      results.push(op === ">=" ? delta >= 0
        : op === "<=" ? delta <= 0
          : op === ">" ? delta > 0
            : op === "<" ? delta < 0
              : delta === 0);
    }
    for (var r = 0; r < results.length; r += 1) {
      if (!results[r]) return false;
    }
    return true;
  }

  function isNormalizedRecord(record) {
    return (record.notes || {}).provenance === PROVENANCE;
  }

  // openwrt_intel.evaluate_candidate —— 分支顺序与返回码逐条对齐
  function evaluateCandidate(osVersion, installedVersion, records) {
    var series = seriesOf(osVersion);
    var device = releaseTuple(osVersion);
    var operatorRows = records.filter(function (r) { return !isNormalizedRecord(r); });
    var normalizedRows = records.filter(isNormalizedRecord);
    var exact = operatorRows.filter(function (r) { return r.release === osVersion; });
    var branchRows = normalizedRows.filter(function (r) {
      return isBranchScope(r.release || "");
    });

    // 1) 操作员/人工精确记录
    if (exact.length) {
      var fixedExact = exact[0].fixed_versions || [];
      var affectedExact = exact[0].affected_versions || [];
      if (fixedExact.indexOf(installedVersion) !== -1) {
        return { status: "fixed", code: "openwrt_exact_fixed_version", confidence: 0.95,
          affected: false, fixed_version: fixedExact[0],
          reason: "版本精确命中人工整理的 OpenWrt 已修复版本记录：" + exact[0].source_url };
      }
      if (affectedExact.indexOf(installedVersion) !== -1) {
        return { status: "affected", code: "openwrt_exact_affected_version", confidence: 0.95,
          affected: true, fixed_version: fixedExact.length ? fixedExact[0] : "",
          reason: "版本精确命中人工整理的 OpenWrt 受影响版本记录：" + exact[0].source_url };
      }
      return { status: "insufficient_data", code: "openwrt_applicability_missing", confidence: 0.35,
        affected: true, fixed_version: "",
        reason: "人工记录未覆盖当前安装版本，需复核；不采用其他发行版修复版本。" };
    }

    // 2) 官方 release 域范围
    var releaseRows = normalizedRows.filter(function (r) {
      return seriesOf(r.release || "") !== "";
    });
    if (releaseRows.length) {
      for (var i = 0; i < releaseRows.length; i += 1) {
        var row = releaseRows[i];
        for (var k = 0; k < row.affected_versions.length; k += 1) {
          var expr = row.affected_versions[k];
          if (versionInRange(osVersion, expr) === true) {
            var fixedList = row.fixed_versions || [];
            var bestFixed = "";
            if (fixedList.length) {
              bestFixed = fixedList.reduce(function (acc, item) {
                if (!acc) return item;
                return cmpTuple(releaseTuple(item), releaseTuple(acc)) > 0 ? item : acc;
              }, "");
            }
            return {
              status: "affected", code: "openwrt_release_range_affected", confidence: 0.9,
              affected: true, fixed_version: bestFixed,
              reason: "官方受影响范围 " + expr + "（" + (row.notes.ghsa_id || "") + "，"
                + row.source_url + "）包含设备固件 " + osVersion + "。",
            };
          }
        }
      }
      var inSeries = [];
      releaseRows.forEach(function (r) {
        (r.fixed_versions || []).forEach(function (f) {
          if (seriesOf(f) === series) {
            var t = releaseTuple(f);
            if (device !== null && t !== null && cmpTuple(device, t) >= 0) inSeries.push(f);
          }
        });
      });
      if (inSeries.length) {
        var best = inSeries.reduce(function (acc, item) {
          return !acc || cmpTuple(releaseTuple(item), releaseTuple(acc)) > 0 ? item : acc;
        }, "");
        return {
          status: "fixed", code: "openwrt_release_boundary_reached", confidence: 0.9,
          affected: false, fixed_version: best,
          reason: "设备固件 " + osVersion + " 已达本系列官方边界 " + best + " 起。",
        };
      }
      for (var s = 0; s < releaseRows.length; s += 1) {
        var statement = (releaseRows[s].notes || {}).fix_statement || {};
        var stFixed = releaseTuple(String(statement.fixed || ""));
        if (statement.covers_later_releases && device !== null && stFixed !== null
          && cmpTuple(device, stFixed) >= 0) {
          return {
            status: "fixed", code: "openwrt_fix_statement_covers_later", confidence: 0.85,
            affected: false, fixed_version: String(statement.fixed),
            reason: "官方声明“" + statement.text + "”覆盖设备固件 " + osVersion + "。",
          };
        }
      }
      var exprs = [];
      releaseRows.forEach(function (r) {
        (r.affected_versions || []).forEach(function (item) {
          if (exprs.indexOf(item) === -1) exprs.push(item);
        });
      });
      exprs.sort();
      return {
        status: "not_affected", code: "openwrt_release_out_of_range", confidence: 0.85,
        affected: false, fixed_version: "",
        reason: "官方受影响范围 " + exprs.join(", ") + " 不含设备固件 " + osVersion
          + "（" + (releaseRows[0].notes.ghsa_id || "") + "，"
          + releaseRows[0].source_url + "）；公告未给出针对该版本的修复声明。",
      };
    }

    // 3) 分支范围
    if (branchRows.length) {
      var note = branchRows[0].notes || {};
      var anchor = /~([0-9a-f]{7,40})/.exec(installedVersion || "");
      var branchFixed = branchRows[0].fixed_versions || [];
      if (branchFixed.length) {
        return { status: "insufficient_data", code: "openwrt_branch_fix_unverifiable",
          confidence: 0.3, affected: true, fixed_version: branchFixed[0],
          reason: "官方范围为分支 " + (note.branch || "main") + "，登记修复 " + branchFixed[0]
            + "；无法从安装版本串与修复版本的先后关系确定性判定，需人工复核。" };
      }
      if (anchor) {
        return { status: "affected", code: "openwrt_branch_range_no_fix", confidence: 0.75,
          affected: true, fixed_version: "",
          reason: "官方受影响范围为 " + (note.branch || "main") + " 分支且截至最新快照未登记任何修复版本"
            + "（" + (note.ghsa_id || "") + "，" + branchRows[0].source_url + "）。" };
      }
      return { status: "insufficient_data", code: "openwrt_branch_version_unverifiable",
        confidence: 0.3, affected: true, fixed_version: "",
        reason: "官方受影响范围为 " + (note.branch || "main") + " 分支且未登记修复版本；"
          + "安装版本串不含源码 commit 锚点，无法判定是否落在范围内。" };
    }

    // 4) 无官方规范化记录可用
    if (operatorRows.length) {
      return { status: "insufficient_data", code: "openwrt_applicability_missing", confidence: 0.35,
        affected: true, fixed_version: "",
        reason: "缺少与当前 OpenWrt 固件版本对应的厂商适用性证据，需复核；不采用其他发行版修复版本。" };
    }
    var scopes = [];
    records.forEach(function (r) {
      var scope = ((r.notes || {}).scope || "?");
      if (scopes.indexOf(scope) === -1) scopes.push(scope);
    });
    scopes.sort();
    return { status: "insufficient_data", code: "openwrt_scope_not_stated", confidence: 0.3,
      affected: true, fixed_version: "",
      reason: "官方公告范围（域 " + scopes.join(", ") + "）未声明设备固件 " + osVersion
        + " 对应的 release 受影响边界；不作安全推断，保持未确定。" };
  }

  var STATUS_MAP = {
    affected: "potentially_affected",
    fixed: "not_in_reported_range",
    not_affected: "not_in_reported_range",
    insufficient_data: "insufficient_data",
  };

  // 与 iot_official._assess_openwrt 的收敛一致（版本-only 评估）
  function classifyOne(advisory, version) {
    var payload = {
      ghsa_id: advisory.ghsa_id,
      cve_id: advisory.cve_id,
      html_url: advisory.source_url,
      summary: advisory.summary,
      description: advisory.description,
      vulnerabilities: (advisory.ranges || []).map(function (r) {
        return {
          package: { name: r.component },
          vulnerable_version_range: r.range,
          first_patched_version: r.first_patched_version || "",
        };
      }),
    };
    var normalized = normalizeAdvisory(payload);
    var outcome = null;
    var components = [];
    for (var i = 0; i < normalized.length; i += 1) {
      components.push(normalized[i].package_name);
      var candidate = evaluateCandidate(version, "", [normalized[i]]);
      if (candidate.code === "openwrt_branch_range_no_fix") {
        candidate = {
          status: "insufficient_data",
          code: "openwrt_branch_scope_version_only",
          confidence: candidate.confidence,
          reason: "官方受影响范围为主干分支且未登记修复版本；仅凭 release 版本参数无法判定，"
            + "需结合设备组件源码锚点。",
        };
      }
      if (outcome === null || candidate.status === "affected") outcome = candidate;
    }
    if (outcome === null) {
      outcome = { status: "insufficient_data", code: "no_records", reason: "无规范化记录。" };
    }
    return {
      advisory_id: advisory.ghsa_id,
      cve_id: advisory.cve_id,
      components: Array.from(new Set(components)).sort(),
      official_ranges: (advisory.ranges || []).map(function (r) { return r.range; }),
      raw_status: outcome.status,
      code: outcome.code,
      confidence: outcome.confidence,
      status: STATUS_MAP[outcome.status],
      reason: outcome.reason,
      normalized_records: normalized.map(function (rec) {
        return {
          package_name: rec.package_name,
          release: rec.release,
          affected_versions: rec.affected_versions,
          fixed_versions: rec.fixed_versions,
          scope: (rec.notes || {}).scope,
          official_range: (rec.notes || {}).official_range,
        };
      }),
    };
  }

  function classify(version, advisories) {
    var results = advisories.map(function (item) { return classifyOne(item, version); });
    var counts = { potentially_affected: 0, insufficient_data: 0, not_in_reported_range: 0 };
    results.forEach(function (item) { counts[item.status] = (counts[item.status] || 0) + 1; });
    return { version: version, advisory_count: results.length, counts: counts, results: results };
  }

  /* 与服务端参照结果逐条比对：状态 + 依据码 + 组件集合。
     不一致时返回明细，绝不静默。 */
  function compareWithReference(mine, reference) {
    var refById = {};
    (reference.results || []).forEach(function (item) { refById[item.advisory_id] = item; });
    var diffs = [];
    var checked = 0;
    (mine.results || []).forEach(function (item) {
      var ref = refById[item.advisory_id];
      if (!ref) {
        diffs.push({ advisory_id: item.advisory_id, field: "missing_reference",
          mine: item.status, reference: null });
        return;
      }
      checked += 1;
      if (ref.status !== item.status) {
        diffs.push({ advisory_id: item.advisory_id, field: "status",
          mine: item.status, reference: ref.status });
      }
      if (ref.code !== item.code) {
        diffs.push({ advisory_id: item.advisory_id, field: "code",
          mine: item.code, reference: ref.code });
      }
      var mineComponents = (item.components || []).slice().sort().join(",");
      var refComponents = (ref.components || []).slice().sort().join(",");
      if (mineComponents !== refComponents) {
        diffs.push({ advisory_id: item.advisory_id, field: "components",
          mine: mineComponents, reference: refComponents });
      }
    });
    return { checked: checked, diffs: diffs, ok: diffs.length === 0 };
  }

  function isValidVersion(version) {
    return /^\d+\.\d+\.\d+$/.test(String(version || ""));
  }

export const IGEngine = {
    releaseTuple: releaseTuple,
    seriesOf: seriesOf,
    parseRange: parseRange,
    normalizeComponents: normalizeComponents,
    normalizeAdvisory: normalizeAdvisory,
    versionInRange: versionInRange,
    evaluateCandidate: evaluateCandidate,
    classify: classify,
    classifyOne: classifyOne,
    compareWithReference: compareWithReference,
    isValidVersion: isValidVersion,
    STATUS_LABEL: {
      potentially_affected: "候选受影响",
      insufficient_data: "证据不足",
      not_in_reported_range: "超出官方范围",
      affected: "已确认受影响",
      fixed: "已修复",
    },
    SOURCE: "openwrt_intel.py#evaluate_candidate / iot_official.py#version_in_range",
  };

export default IGEngine;
