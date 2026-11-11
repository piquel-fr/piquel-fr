-- Event consumers' cursors were never used outside tests: no release reads or
-- writes event_consumers, so it goes now. Alerts (#83) add the cursor they need
-- when they read the stream.
DROP TABLE event_consumers;

-- No channel ever ordered its deliveries, so auth no longer reads or writes
-- deliveries.ordering_key, deliveries.ordinal or delivery_orderings.
--
-- PENDING CONTRACT: they stay, because the previous release still names them
-- when it inserts, claims and lists deliveries. Once no deployed release does,
-- a new migration must DROP TABLE delivery_orderings, then drop both columns,
-- which takes their UNIQUE and CHECK constraints with them.
