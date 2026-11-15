/* SPDX-License-Identifier: LicenseRef-SPL-1.0 */
'use strict';
// Host integration fixtures, NOT a policy VM or production authority server.
// session and state must originate from authenticated server infrastructure.
// Only the requested resource is consumed from the client; client facts are ignored.
function lookup(table, command) {
 const id = command && command.resourceId;
 return typeof id === 'string' && Object.hasOwn(table, id) ? table[id] : undefined;
}
function doorFacts(session, state, command) {
 const door = lookup(state.doors, command);
 return Object.freeze({authenticated:session.authenticated === true,
   exists:!!door, authorized:!!door && door.allowedActors.includes(session.actorId),
   unlocked:!!door && !door.locked});
}
function inventoryFacts(session, state, command) {
 const item = lookup(state.items, command);
 return Object.freeze({authenticated:session.authenticated === true,
   exists:!!item, owns:!!item && item.owner === session.actorId,
   unreserved:!!item && item.reservation === null});
}
function raceFacts(session, state, command) {
 const race = lookup(state.races, command);
 return Object.freeze({authenticated:session.authenticated === true,
   exists:!!race, entered:!!race && race.entrants.includes(session.actorId),
   racing:!!race && race.phase === 'racing'});
}
module.exports = {doorFacts,inventoryFacts,raceFacts};
