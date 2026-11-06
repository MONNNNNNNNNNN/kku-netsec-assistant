// Zabbix webhook media type "NetSec Board" (Alerts > Media types > Create, type Webhook).
// Parameters (name = value):
//   board_url = https://netsec-board.example.kku.ac.th
//   token     = <hooks.zabbix.token from netsec.json>
//   eventid   = {EVENT.ID}          triggerid = {TRIGGER.ID}
//   severity  = {EVENT.NSEVERITY}   status    = {EVENT.STATUS}   (PROBLEM / RESOLVED)
//   name      = {EVENT.NAME}        host      = {HOST.NAME}       opdata = {EVENT.OPDATA}
// Use it in an action for problem and recovery operations. Read-only for Zabbix: it only POSTs.
// Make sure the media type is Enabled (one created through the API is disabled by default), and give
// the action's user a media entry of this type. Tested against Zabbix 7.0.32 (lab/x4-zabbix.js).
var params = JSON.parse(value);
var req = new HttpRequest();
req.addHeader('Content-Type: application/json');
req.addHeader('Authorization: Bearer ' + params.token);
var body = {
  eventid: params.eventid, triggerid: params.triggerid, severity: params.severity,
  status: params.status, name: params.name, host: params.host, opdata: params.opdata
};
var resp = req.post(params.board_url.replace(/\/+$/, '') + '/hooks/zabbix', JSON.stringify(body));
if (req.getStatus() !== 202) {
  throw 'NetSec Board HTTP ' + req.getStatus() + ': ' + resp;
}
return 'OK';
