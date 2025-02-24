def get_bill_data(connection, customer_id, connection_id, month, year):
    cursor = connection.cursor()

    test_query = f"""
    SELECT
    *
    FROM
        CUSTOMERS
        JOIN CONNECTIONS C
        ON CUSTOMERS.CUSTOMERID = C.CUSTOMERID
    WHERE
        C.CUSTOMERID = '{customer_id}'
        and c.connectionid = '{connection_id}'
    """

    cursor.execute(test_query)
    test_data = cursor.fetchone()

    if not test_data:
        raise Exception("Customer or connection ID not found")

    customer_query = f"""
    select FirstName, LastName, Address, PhoneNumber, Email
    from customers
    where customerid = '{customer_id}'
    """

    cursor.execute(customer_query)
    customer_data = cursor.fetchone()

    connections_query = f"""
    select ct.description, d.divisionname, d.subdivname, con.installationdate, con.metertype
    from connections con
    join connectiontypes ct on con.connectiontypecode = ct.connectiontypecode
    join divinfo d on (con.divisionid = d.divisionid and con.subdivid = d.subdivid)
    where connectionid = '{connection_id}'
    """

    cursor.execute(connections_query)
    connections_data = cursor.fetchone()

    bill_query = f"""
    select b.billissuedate, b.net_peakunits, b.net_offpeakunits, b.taxamount, b.fixedfee, b.arrears, b.duedate, b.totalamount_beforeduedate, b.totalamount_afterduedate
    from bill b
    where b.connectionid = '{connection_id}'
    and b.billingmonth = {month}
    and b.billingyear = {year}
    """

    cursor.execute(bill_query)
    bill_data = cursor.fetchone()

    tariffs_query1 = f"""
    select net_peakunits, net_offpeakunits, peakamount, offpeakamount, billissuedate, import_peakunits, import_offpeakunits
    from bill
    where connectionid = '{connection_id}'
    """

    cursor.execute(tariffs_query1)
    tariffs_data1 = cursor.fetchone()

    billingdays = cursor.callfunc(
        'FUN_COMPUTE_BILLINGDAYS',  
        float,
        [connection_id, month, year]
    )

    ahpc = tariffs_data1[5]/(billingdays*24)
    ahoc = tariffs_data1[1]/(billingdays*24)

    billissuedate = tariffs_data1[4]

    tariffs_query2 = f"""
    select tarrifdescription, rateperunit
    from tariff
    join connections on connections.connectiontypecode = tariff.connectiontypecode
    where :billissuedate between tariff.startdate and tariff.enddate 
    and {ahpc} between tariff.thresholdlow_perhour and tariff.thresholdhigh_perhour
    and connections.connectionid = '{connection_id}'
    """

    cursor.execute(tariffs_query2, {
    'billissuedate': billissuedate})
    tariffs_data2 = cursor.fetchone()

    tariffs_query3 = f"""
    select tarrifdescription, rateperunit
    from tariff
    join connections on connections.connectiontypecode = tariff.connectiontypecode
    where (:billissuedate between startdate and enddate) 
    and ({ahoc} between thresholdlow_perhour and thresholdhigh_perhour)
    and connections.connectionid = '{connection_id}'
    """

    cursor.execute(tariffs_query3, {
    'billissuedate': billissuedate})
    tariffs_data3 = cursor.fetchone()

    taxes_query = f"""
    select taxtype, rate
    from taxrates tr
    join connections c on c.connectiontypecode = tr.connectiontypecode
    where c.connectionid = '{connection_id}'
    """

    cursor.execute(taxes_query)
    taxes_data = cursor.fetchall()

    units_per_hour = (tariffs_data1[5] + tariffs_data1[6])/(billingdays * 24)

    subsidy_query = f"""
    SELECT
        s.subsidycode, s.rateperunit, sp.providername
    FROM
        SUBSIDY     S
        join subsidyprovider sp
        on s.providerid = sp.providerid
        JOIN CONNECTIONS C
        ON S.CONNECTIONTYPECODE = C.CONNECTIONTYPECODE
    WHERE
        C.CONNECTIONID = '{connection_id}'
        AND (:billissuedate BETWEEN S.STARTDATE
        AND S.ENDDATE)
    """

    cursor.execute(subsidy_query, {'billissuedate': billissuedate})
    subsidy_data = cursor.fetchall()

    ff_query = f"""
    select f.fixedchargetype, f.fixedfee
    from fixedcharges f
    join connections c on c.connectiontypecode = f.connectiontypecode
    where
    C.CONNECTIONID = '{connection_id}'
    and :billissuedate between f.startdate and f.enddate
    
    """

    cursor.execute(ff_query, {'billissuedate': billissuedate})
    ff_data = cursor.fetchall()

    bills_prev_query = f"""
    select b.billingmonth, b.billingyear, b.totalamount_beforeduedate, b.duedate, p.paymentstatus
    from bill b
    join paymentdetails p on b.billid = p.billid
    where b.connectionid = '{connection_id}'
    
    """

    cursor.execute(bills_prev_query)
    bills_prev_data = cursor.fetchmany(size=10)
    
    return customer_data, connections_data, bill_data, tariffs_data1, tariffs_data2, tariffs_data3, taxes_data, subsidy_data, ff_data, bills_prev_data