.. _extended_select_into_outfile:

===========================================
 Extended ``SELECT INTO OUTFILE/DUMPFILE``
===========================================

*Percona Server for MySQL* has extended the ``SELECT INTO ... OUTFILE`` and ``SELECT INTO DUMPFILE`` `commands <http://dev.mysql.com/doc/refman/5.7/en/select-into.html>`_ to add the support for UNIX sockets and named pipes. Before this was implemented the database would return an error for such files. 

This feature allows using ``LOAD DATA LOCAL INFILE`` in combination with ``SELECT INTO OUTFILE`` to quickly load multiple partitions across the network or in other setups, without having to use an intermediate file which wastes space and I/O.

Version Specific Information
============================
* :ref:`5.7.10-1`: Feature ported from *Percona Server for MySQL* 5.6 

Other Reading
=============
* MySQL bug: :mysqlbug:`44835`
