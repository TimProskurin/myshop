--
-- PostgreSQL database dump
--

-- Dumped from database version 16.3
-- Dumped by pg_dump version 17.1

-- Started on 2025-05-22 13:00:02

SET statement_timeout = 0;
SET lock_timeout = 0;
SET idle_in_transaction_session_timeout = 0;
SET transaction_timeout = 0;
SET client_encoding = 'UTF8';
SET standard_conforming_strings = on;
SELECT pg_catalog.set_config('search_path', '', false);
SET check_function_bodies = false;
SET xmloption = content;
SET client_min_messages = warning;
SET row_security = off;

--
-- TOC entry 2 (class 3079 OID 16537)
-- Name: pgcrypto; Type: EXTENSION; Schema: -; Owner: -
--

CREATE EXTENSION IF NOT EXISTS pgcrypto WITH SCHEMA public;


--
-- TOC entry 5037 (class 0 OID 0)
-- Dependencies: 2
-- Name: EXTENSION pgcrypto; Type: COMMENT; Schema: -; Owner: 
--

COMMENT ON EXTENSION pgcrypto IS 'cryptographic functions';


--
-- TOC entry 270 (class 1255 OID 16574)
-- Name: check_login_attempts(integer); Type: FUNCTION; Schema: public; Owner: postgres
--

CREATE FUNCTION public.check_login_attempts(user_id integer) RETURNS void
    LANGUAGE plpgsql
    AS $$
DECLARE
    failed_attempts INT;
BEGIN
    SELECT COUNT(*) INTO failed_attempts
    FROM login_attempts
    WHERE user_id = check_login_attempts.user_id
      AND is_successful = FALSE
      AND attempt_time > NOW() - INTERVAL '15 minutes';

    IF failed_attempts >= 3 THEN
        UPDATE users
        SET is_locked = TRUE
        WHERE user_id = check_login_attempts.user_id;
    END IF;
END;
$$;


ALTER FUNCTION public.check_login_attempts(user_id integer) OWNER TO postgres;

--
-- TOC entry 271 (class 1255 OID 16575)
-- Name: current_user_id(); Type: FUNCTION; Schema: public; Owner: postgres
--

CREATE FUNCTION public.current_user_id() RETURNS integer
    LANGUAGE plpgsql
    AS $$
DECLARE
    user_id INT;
BEGIN
    -- Получаем email текущего пользователя
    SELECT users.user_id INTO user_id FROM Users WHERE email = SESSION_USER; -- или используйте current_user, если нужно
    RETURN user_id;
EXCEPTION
    WHEN NO_DATA_FOUND THEN
        RETURN NULL; -- если пользователь не найден
END;
$$;


ALTER FUNCTION public.current_user_id() OWNER TO postgres;

--
-- TOC entry 272 (class 1255 OID 16576)
-- Name: encrypt_payment_data(); Type: FUNCTION; Schema: public; Owner: postgres
--

CREATE FUNCTION public.encrypt_payment_data() RETURNS trigger
    LANGUAGE plpgsql
    AS $$
DECLARE
    secret_key TEXT := 'key';
BEGIN
    
    NEW.card_number := pgp_sym_encrypt(NEW.card_number, 'encryption_key', 'compress-algo=1, cipher-algo=aes256');
    NEW.expiration_date := pgp_sym_encrypt(NEW.expiration_date, 'encryption_key', 'compress-algo=1, cipher-algo=aes256');
    
    RETURN NEW;
END;
$$;


ALTER FUNCTION public.encrypt_payment_data() OWNER TO postgres;

--
-- TOC entry 277 (class 1255 OID 16577)
-- Name: get_decrypted_address(integer); Type: FUNCTION; Schema: public; Owner: postgres
--

CREATE FUNCTION public.get_decrypted_address(p_user_id integer) RETURNS text
    LANGUAGE plpgsql
    AS $$
DECLARE
    address BYTEA;
    encryption_key BYTEA;
    decrypted_address TEXT;
BEGIN
    -- Извлечение зашифрованного адреса и ключа шифрования для пользователя
    SELECT 
        u.address, 
        e.encryption_key
    INTO 
        address, 
        encryption_key
    FROM 
        Users u
    JOIN 
        EncryptionKeys e ON u.user_id = e.user_id
    WHERE 
        u.user_id = p_user_id; 

    IF address IS NULL OR encryption_key IS NULL THEN
        RAISE EXCEPTION 'No data found for user ID %', p_user_id;
    END IF;

    decrypted_address := pgp_sym_decrypt(address, encode(encryption_key, 'hex'));

    RETURN decrypted_address;
END;
$$;


ALTER FUNCTION public.get_decrypted_address(p_user_id integer) OWNER TO postgres;

--
-- TOC entry 285 (class 1255 OID 16578)
-- Name: get_user_info(); Type: FUNCTION; Schema: public; Owner: postgres
--

CREATE FUNCTION public.get_user_info() RETURNS TABLE(user_id integer, first_name character varying, last_name character varying, email character varying, phone character varying, decrypted_address text)
    LANGUAGE plpgsql
    AS $$
BEGIN
    RETURN QUERY 
    SELECT 
        u.user_id,
        u.first_name,
        u.last_name,
        u.email,
        u.phone,
        pgp_sym_decrypt(u.address::bytea, e.encryption_key) AS decrypted_address
    FROM 
        Users u
    JOIN 
        encryptionkeys e ON u.user_id = e.user_id
    WHERE 
        u.email = current_user;  -- предполагаем, что email является уникальным идентификатором
END;
$$;


ALTER FUNCTION public.get_user_info() OWNER TO postgres;

--
-- TOC entry 286 (class 1255 OID 16579)
-- Name: hash_password(); Type: FUNCTION; Schema: public; Owner: postgres
--

CREATE FUNCTION public.hash_password() RETURNS trigger
    LANGUAGE plpgsql
    AS $$
BEGIN
    NEW.password := crypt(NEW.password, gen_salt('bf'));
    RETURN NEW;
END;
$$;


ALTER FUNCTION public.hash_password() OWNER TO postgres;

--
-- TOC entry 287 (class 1255 OID 16580)
-- Name: insert_user(character varying, character varying, character varying, character varying, character varying, character varying); Type: FUNCTION; Schema: public; Owner: postgres
--

CREATE FUNCTION public.insert_user(p_first_name character varying, p_last_name character varying, p_email character varying, p_password character varying, p_phone character varying, p_address character varying) RETURNS void
    LANGUAGE plpgsql
    AS $$
DECLARE
    new_encryption_key BYTEA := gen_random_bytes(32); 
    new_user_id INT; 
BEGIN 
    INSERT INTO Users (first_name, last_name, email, password, phone, 
                       address, registration_date)
    VALUES (
        p_first_name,
        p_last_name,
        p_email,
        p_password,
        p_phone,
        pgp_sym_encrypt(p_address, encode(new_encryption_key, 'hex')), 
        CURRENT_TIMESTAMP
    )
    RETURNING user_id INTO new_user_id;

    INSERT INTO EncryptionKeys (user_id, encryption_key)
    VALUES (new_user_id, new_encryption_key);
END;
$$;


ALTER FUNCTION public.insert_user(p_first_name character varying, p_last_name character varying, p_email character varying, p_password character varying, p_phone character varying, p_address character varying) OWNER TO postgres;

--
-- TOC entry 288 (class 1255 OID 16581)
-- Name: log_role_user_changes(); Type: FUNCTION; Schema: public; Owner: postgres
--

CREATE FUNCTION public.log_role_user_changes() RETURNS event_trigger
    LANGUAGE plpgsql
    AS $$
DECLARE
    obj_name TEXT;
BEGIN
    
    IF (TG_TAG = 'CREATE ROLE') THEN
        obj_name := (SELECT rolname FROM pg_roles WHERE oid = (SELECT objid FROM pg_event_trigger_ddl_commands() LIMIT 1));
        INSERT INTO role_user_audit (action, object_name, user_name) 
        VALUES ('CREATE ROLE', obj_name, current_user);
    END IF;

   
    IF (TG_TAG = 'DROP ROLE') THEN
        obj_name := (SELECT rolname FROM pg_roles WHERE oid = (SELECT objid FROM pg_event_trigger_ddl_commands() LIMIT 1));
        INSERT INTO role_user_audit (action, object_name, user_name) 
        VALUES ('DROP ROLE', obj_name, current_user);
    END IF;

    
    IF (TG_TAG = 'ALTER ROLE') THEN
        obj_name := (SELECT rolname FROM pg_roles WHERE oid = (SELECT objid FROM pg_event_trigger_ddl_commands() LIMIT 1));
        INSERT INTO role_user_audit (action, object_name, user_name) 
        VALUES ('ALTER ROLE', obj_name, current_user);
    END IF;

    
    IF (TG_TAG = 'CREATE USER') THEN
        obj_name := (SELECT usename FROM pg_user WHERE usesysid = (SELECT objid FROM pg_event_trigger_ddl_commands() LIMIT 1));
        INSERT INTO role_user_audit (action, object_name, user_name) 
        VALUES ('CREATE USER', obj_name, current_user);
    END IF;

   
    IF (TG_TAG = 'DROP USER') THEN
        obj_name := (SELECT usename FROM pg_user WHERE usesysid = (SELECT objid FROM pg_event_trigger_ddl_commands() LIMIT 1));
        INSERT INTO role_user_audit (action, object_name, user_name) 
        VALUES ('DROP USER', obj_name, current_user);
    END IF;

   
    IF (TG_TAG = 'ALTER USER') THEN
        obj_name := (SELECT usename FROM pg_user WHERE usesysid = (SELECT objid FROM pg_event_trigger_ddl_commands() LIMIT 1));
        INSERT INTO role_user_audit (action, object_name, user_name) 
        VALUES ('ALTER USER', obj_name, current_user);
    END IF;
END; 
$$;


ALTER FUNCTION public.log_role_user_changes() OWNER TO postgres;

--
-- TOC entry 289 (class 1255 OID 16582)
-- Name: log_user_changes(); Type: FUNCTION; Schema: public; Owner: postgres
--

CREATE FUNCTION public.log_user_changes() RETURNS trigger
    LANGUAGE plpgsql
    AS $$
BEGIN
    IF (TG_OP = 'INSERT') THEN
        INSERT INTO user_logs(user_id, action, new_data)
        VALUES (NEW.user_id, 'INSERT', row_to_json(NEW));

        RETURN NEW;
    
    ELSIF (TG_OP = 'UPDATE') THEN
        INSERT INTO user_logs(user_id, action, old_data, new_data)
        VALUES (OLD.user_id, 'UPDATE', row_to_json(OLD), row_to_json(NEW));

        RETURN NEW;
    
    ELSIF (TG_OP = 'DELETE') THEN
        INSERT INTO user_logs(user_id, action, old_data)
        VALUES (OLD.user_id, 'DELETE', row_to_json(OLD));

        RETURN OLD;
    END IF;

    RETURN NULL;
END;
$$;


ALTER FUNCTION public.log_user_changes() OWNER TO postgres;

SET default_tablespace = '';

SET default_table_access_method = heap;

--
-- TOC entry 216 (class 1259 OID 16583)
-- Name: categories; Type: TABLE; Schema: public; Owner: postgres
--

CREATE TABLE public.categories (
    category_id integer NOT NULL,
    category_name character varying(100),
    description text
);


ALTER TABLE public.categories OWNER TO postgres;

--
-- TOC entry 217 (class 1259 OID 16588)
-- Name: categories_category_id_seq; Type: SEQUENCE; Schema: public; Owner: postgres
--

CREATE SEQUENCE public.categories_category_id_seq
    AS integer
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


ALTER SEQUENCE public.categories_category_id_seq OWNER TO postgres;

--
-- TOC entry 5038 (class 0 OID 0)
-- Dependencies: 217
-- Name: categories_category_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: postgres
--

ALTER SEQUENCE public.categories_category_id_seq OWNED BY public.categories.category_id;


--
-- TOC entry 218 (class 1259 OID 16589)
-- Name: delivery; Type: TABLE; Schema: public; Owner: postgres
--

CREATE TABLE public.delivery (
    delivery_id integer NOT NULL,
    order_id integer,
    tracking_number character varying(255),
    courier_service character varying(100),
    delivery_status character varying(50),
    estimated_delivery_date date
);


ALTER TABLE public.delivery OWNER TO postgres;

--
-- TOC entry 219 (class 1259 OID 16592)
-- Name: delivery_delivery_id_seq; Type: SEQUENCE; Schema: public; Owner: postgres
--

CREATE SEQUENCE public.delivery_delivery_id_seq
    AS integer
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


ALTER SEQUENCE public.delivery_delivery_id_seq OWNER TO postgres;

--
-- TOC entry 5039 (class 0 OID 0)
-- Dependencies: 219
-- Name: delivery_delivery_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: postgres
--

ALTER SEQUENCE public.delivery_delivery_id_seq OWNED BY public.delivery.delivery_id;


--
-- TOC entry 220 (class 1259 OID 16593)
-- Name: encryptionkeys; Type: TABLE; Schema: public; Owner: postgres
--

CREATE TABLE public.encryptionkeys (
    key_id integer NOT NULL,
    user_id integer,
    encryption_key character varying(255) NOT NULL
);


ALTER TABLE public.encryptionkeys OWNER TO postgres;

--
-- TOC entry 221 (class 1259 OID 16596)
-- Name: encryptionkeys_key_id_seq; Type: SEQUENCE; Schema: public; Owner: postgres
--

CREATE SEQUENCE public.encryptionkeys_key_id_seq
    AS integer
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


ALTER SEQUENCE public.encryptionkeys_key_id_seq OWNER TO postgres;

--
-- TOC entry 5040 (class 0 OID 0)
-- Dependencies: 221
-- Name: encryptionkeys_key_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: postgres
--

ALTER SEQUENCE public.encryptionkeys_key_id_seq OWNED BY public.encryptionkeys.key_id;


--
-- TOC entry 222 (class 1259 OID 16597)
-- Name: orderitems; Type: TABLE; Schema: public; Owner: postgres
--

CREATE TABLE public.orderitems (
    order_item_id integer NOT NULL,
    order_id integer,
    product_id integer,
    quantity integer,
    price numeric(10,2)
);


ALTER TABLE public.orderitems OWNER TO postgres;

--
-- TOC entry 223 (class 1259 OID 16600)
-- Name: orderitems_order_item_id_seq; Type: SEQUENCE; Schema: public; Owner: postgres
--

CREATE SEQUENCE public.orderitems_order_item_id_seq
    AS integer
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


ALTER SEQUENCE public.orderitems_order_item_id_seq OWNER TO postgres;

--
-- TOC entry 5041 (class 0 OID 0)
-- Dependencies: 223
-- Name: orderitems_order_item_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: postgres
--

ALTER SEQUENCE public.orderitems_order_item_id_seq OWNED BY public.orderitems.order_item_id;


--
-- TOC entry 224 (class 1259 OID 16601)
-- Name: orders; Type: TABLE; Schema: public; Owner: postgres
--

CREATE TABLE public.orders (
    order_id integer NOT NULL,
    user_id integer,
    total_amount numeric(10,2),
    status character varying(50),
    order_date timestamp without time zone DEFAULT CURRENT_TIMESTAMP,
    address character varying(255)
);


ALTER TABLE public.orders OWNER TO postgres;

--
-- TOC entry 225 (class 1259 OID 16605)
-- Name: orders_order_id_seq; Type: SEQUENCE; Schema: public; Owner: postgres
--

CREATE SEQUENCE public.orders_order_id_seq
    AS integer
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


ALTER SEQUENCE public.orders_order_id_seq OWNER TO postgres;

--
-- TOC entry 5042 (class 0 OID 0)
-- Dependencies: 225
-- Name: orders_order_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: postgres
--

ALTER SEQUENCE public.orders_order_id_seq OWNED BY public.orders.order_id;


--
-- TOC entry 226 (class 1259 OID 16606)
-- Name: payments; Type: TABLE; Schema: public; Owner: postgres
--

CREATE TABLE public.payments (
    payment_id integer NOT NULL,
    order_id integer,
    payment_method character varying(50),
    payment_status character varying(50),
    payment_date timestamp without time zone DEFAULT CURRENT_TIMESTAMP,
    card_number text,
    expiration_date text
);


ALTER TABLE public.payments OWNER TO postgres;

--
-- TOC entry 227 (class 1259 OID 16612)
-- Name: payments_payment_id_seq; Type: SEQUENCE; Schema: public; Owner: postgres
--

CREATE SEQUENCE public.payments_payment_id_seq
    AS integer
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


ALTER SEQUENCE public.payments_payment_id_seq OWNER TO postgres;

--
-- TOC entry 5043 (class 0 OID 0)
-- Dependencies: 227
-- Name: payments_payment_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: postgres
--

ALTER SEQUENCE public.payments_payment_id_seq OWNED BY public.payments.payment_id;


--
-- TOC entry 228 (class 1259 OID 16613)
-- Name: products; Type: TABLE; Schema: public; Owner: postgres
--

CREATE TABLE public.products (
    product_id integer NOT NULL,
    category_id integer,
    product_name character varying(255),
    description text,
    price numeric(10,2),
    stock integer,
    created_at timestamp without time zone DEFAULT CURRENT_TIMESTAMP,
    image character varying,
    long_description character varying
);


ALTER TABLE public.products OWNER TO postgres;

--
-- TOC entry 229 (class 1259 OID 16619)
-- Name: products_product_id_seq; Type: SEQUENCE; Schema: public; Owner: postgres
--

CREATE SEQUENCE public.products_product_id_seq
    AS integer
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


ALTER SEQUENCE public.products_product_id_seq OWNER TO postgres;

--
-- TOC entry 5044 (class 0 OID 0)
-- Dependencies: 229
-- Name: products_product_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: postgres
--

ALTER SEQUENCE public.products_product_id_seq OWNED BY public.products.product_id;


--
-- TOC entry 230 (class 1259 OID 16620)
-- Name: user_logs; Type: TABLE; Schema: public; Owner: postgres
--

CREATE TABLE public.user_logs (
    log_id integer NOT NULL,
    user_id integer,
    action character varying(50),
    old_data jsonb,
    new_data jsonb,
    changed_at timestamp without time zone DEFAULT CURRENT_TIMESTAMP
);


ALTER TABLE public.user_logs OWNER TO postgres;

--
-- TOC entry 231 (class 1259 OID 16626)
-- Name: user_logs_log_id_seq; Type: SEQUENCE; Schema: public; Owner: postgres
--

CREATE SEQUENCE public.user_logs_log_id_seq
    AS integer
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


ALTER SEQUENCE public.user_logs_log_id_seq OWNER TO postgres;

--
-- TOC entry 5045 (class 0 OID 0)
-- Dependencies: 231
-- Name: user_logs_log_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: postgres
--

ALTER SEQUENCE public.user_logs_log_id_seq OWNED BY public.user_logs.log_id;


--
-- TOC entry 232 (class 1259 OID 16627)
-- Name: users; Type: TABLE; Schema: public; Owner: postgres
--

CREATE TABLE public.users (
    user_id integer NOT NULL,
    first_name character varying(100),
    last_name character varying(100),
    email character varying(255),
    phone character varying(20),
    address character varying(255),
    registration_date timestamp without time zone DEFAULT CURRENT_TIMESTAMP,
    password character varying(255),
    secret_key character varying(255),
    two_fa_enabled boolean DEFAULT false
);


ALTER TABLE public.users OWNER TO postgres;

--
-- TOC entry 233 (class 1259 OID 16633)
-- Name: users_user_id_seq; Type: SEQUENCE; Schema: public; Owner: postgres
--

CREATE SEQUENCE public.users_user_id_seq
    AS integer
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


ALTER SEQUENCE public.users_user_id_seq OWNER TO postgres;

--
-- TOC entry 5046 (class 0 OID 0)
-- Dependencies: 233
-- Name: users_user_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: postgres
--

ALTER SEQUENCE public.users_user_id_seq OWNED BY public.users.user_id;


--
-- TOC entry 4821 (class 2604 OID 16634)
-- Name: categories category_id; Type: DEFAULT; Schema: public; Owner: postgres
--

ALTER TABLE ONLY public.categories ALTER COLUMN category_id SET DEFAULT nextval('public.categories_category_id_seq'::regclass);


--
-- TOC entry 4822 (class 2604 OID 16635)
-- Name: delivery delivery_id; Type: DEFAULT; Schema: public; Owner: postgres
--

ALTER TABLE ONLY public.delivery ALTER COLUMN delivery_id SET DEFAULT nextval('public.delivery_delivery_id_seq'::regclass);


--
-- TOC entry 4823 (class 2604 OID 16636)
-- Name: encryptionkeys key_id; Type: DEFAULT; Schema: public; Owner: postgres
--

ALTER TABLE ONLY public.encryptionkeys ALTER COLUMN key_id SET DEFAULT nextval('public.encryptionkeys_key_id_seq'::regclass);


--
-- TOC entry 4824 (class 2604 OID 16637)
-- Name: orderitems order_item_id; Type: DEFAULT; Schema: public; Owner: postgres
--

ALTER TABLE ONLY public.orderitems ALTER COLUMN order_item_id SET DEFAULT nextval('public.orderitems_order_item_id_seq'::regclass);


--
-- TOC entry 4825 (class 2604 OID 16638)
-- Name: orders order_id; Type: DEFAULT; Schema: public; Owner: postgres
--

ALTER TABLE ONLY public.orders ALTER COLUMN order_id SET DEFAULT nextval('public.orders_order_id_seq'::regclass);


--
-- TOC entry 4827 (class 2604 OID 16639)
-- Name: payments payment_id; Type: DEFAULT; Schema: public; Owner: postgres
--

ALTER TABLE ONLY public.payments ALTER COLUMN payment_id SET DEFAULT nextval('public.payments_payment_id_seq'::regclass);


--
-- TOC entry 4829 (class 2604 OID 16640)
-- Name: products product_id; Type: DEFAULT; Schema: public; Owner: postgres
--

ALTER TABLE ONLY public.products ALTER COLUMN product_id SET DEFAULT nextval('public.products_product_id_seq'::regclass);


--
-- TOC entry 4831 (class 2604 OID 16641)
-- Name: user_logs log_id; Type: DEFAULT; Schema: public; Owner: postgres
--

ALTER TABLE ONLY public.user_logs ALTER COLUMN log_id SET DEFAULT nextval('public.user_logs_log_id_seq'::regclass);


--
-- TOC entry 4833 (class 2604 OID 16642)
-- Name: users user_id; Type: DEFAULT; Schema: public; Owner: postgres
--

ALTER TABLE ONLY public.users ALTER COLUMN user_id SET DEFAULT nextval('public.users_user_id_seq'::regclass);


--
-- TOC entry 5014 (class 0 OID 16583)
-- Dependencies: 216
-- Data for Name: categories; Type: TABLE DATA; Schema: public; Owner: postgres
--

COPY public.categories (category_id, category_name, description) FROM stdin;
1	Smartphones	Latest models of smartphones from top brands
2	Laptops	Wide range of laptops including gaming and business models
3	TV & Audio	Televisions, sound systems, and accessories
4	Home Appliances	Refrigerators, washing machines, microwaves and other appliances
5	Cameras & Photo	Digital cameras, lenses, and photography equipment
6	Computer Accessories	Keyboards, mice, monitors, and other peripherals
\.


--
-- TOC entry 5016 (class 0 OID 16589)
-- Dependencies: 218
-- Data for Name: delivery; Type: TABLE DATA; Schema: public; Owner: postgres
--

COPY public.delivery (delivery_id, order_id, tracking_number, courier_service, delivery_status, estimated_delivery_date) FROM stdin;
1	1	TRACK123456	DHL	in transit	2024-10-25
2	2	TRACK654321	FedEx	delivered	2024-10-20
3	3	TRACK987654	UPS	shipped	2024-10-23
4	4	TRACK321654	DHL	canceled	2024-10-19
5	5	TRACK111222	FedEx	in transit	2024-10-26
\.


--
-- TOC entry 5018 (class 0 OID 16593)
-- Dependencies: 220
-- Data for Name: encryptionkeys; Type: TABLE DATA; Schema: public; Owner: postgres
--

COPY public.encryptionkeys (key_id, user_id, encryption_key) FROM stdin;
1	9	f33fa5e1-0c01-4208-83fd-d4711a3b47d1
2	11	\\x6ecdc3effa9a700d6135df94d8b7e74d38c87320eb1202d9d9f3f56e54f1378d
3	12	\\xb958ba6a6350aea9aec4e11e93b8b9bceb6b2a1545a803b7caef8c13d3f60627
\.


--
-- TOC entry 5020 (class 0 OID 16597)
-- Dependencies: 222
-- Data for Name: orderitems; Type: TABLE DATA; Schema: public; Owner: postgres
--

COPY public.orderitems (order_item_id, order_id, product_id, quantity, price) FROM stdin;
1	1	2	1	239999.00
2	1	6	1	9999.00
3	2	1	1	129999.00
4	2	5	1	59999.00
5	3	3	1	79999.00
6	4	6	1	9999.00
7	5	4	1	129999.00
\.


--
-- TOC entry 5022 (class 0 OID 16601)
-- Dependencies: 224
-- Data for Name: orders; Type: TABLE DATA; Schema: public; Owner: postgres
--

COPY public.orders (order_id, user_id, total_amount, status, order_date, address) FROM stdin;
1	1	229998.00	pending	2024-10-17 15:47:22.655937	Moscow, Tverskaya St, 12
2	2	149998.00	completed	2024-10-17 15:47:22.655937	Saint Petersburg, Nevsky Ave, 24
3	3	79999.00	shipped	2024-10-17 15:47:22.655937	Novosibirsk, Lenin St, 3
4	4	9999.00	canceled	2024-10-17 15:47:22.655937	Kazan, Bauman St, 5
5	5	239999.00	pending	2024-10-17 15:47:22.655937	Yekaterinburg, Vysotsky St, 8
\.


--
-- TOC entry 5024 (class 0 OID 16606)
-- Dependencies: 226
-- Data for Name: payments; Type: TABLE DATA; Schema: public; Owner: postgres
--

COPY public.payments (payment_id, order_id, payment_method, payment_status, payment_date, card_number, expiration_date) FROM stdin;
1	1	credit card	paid	2024-10-17 15:47:22.655937	\N	\N
2	2	paypal	paid	2024-10-17 15:47:22.655937	\N	\N
3	3	credit card	paid	2024-10-17 15:47:22.655937	\N	\N
4	4	paypal	failed	2024-10-17 15:47:22.655937	\N	\N
5	5	credit card	pending	2024-10-17 15:47:22.655937	\N	\N
10	1	credit card	paid	2024-10-17 17:45:39.862565	\\xc30d04090302d38912fb2369b64274d24901b5df1d733d479706a66bec25069777cbe7f41a6d4b8d1dfffe1c66a6f47d6c8c2b2bd9848eaac95a7d06a5775b026ea55dbbaeda6679bb9eb916f61c2d7d08fa87b15687e52b08f0	\\xc30d04090302b0e6c3e6335885f876d23b019fa2c55e413284fad8e375c47d4925b6a7745dfc3fa0f97468b64f48b5bcfacfff66c8dfe52497c3ee6fa787122aecb6c1e5970e63dec110e1b9
11	2	paypal	paid	2024-10-17 17:45:39.862565	\\xc30d04090302325298b9337950bd6cd24901c4e31004d5e4055194437674fd24c27e367c91e169fb733c1dd359434a150b264e0c8400ec767de318543504f6af755bbda3b6b562c41979ef250be0ec65d5ffd15607695343e84e	\\xc30d04090302392ffc92fbc97e0e78d23b01b9e05bbb88fec40e464b6e7caf70d1726ffaf6aec1a458824a8d804e9d86663d1bcebe87fecd6e1ca349ecde37e9fe3cac529c6443df349dd633
\.


--
-- TOC entry 5026 (class 0 OID 16613)
-- Dependencies: 228
-- Data for Name: products; Type: TABLE DATA; Schema: public; Owner: postgres
--

COPY public.products (product_id, category_id, product_name, description, price, stock, created_at, image, long_description) FROM stdin;
2	1	Samsung Galaxy S23	Samsung Galaxy S23 with 128GB storage, 5G support	99999.00	150	2024-10-17 15:47:22.655937	\N	\N
3	2	MacBook Pro 16"	Apple MacBook Pro 16-inch with M2 chip and 512GB SSD	239999.00	50	2024-10-17 15:47:22.655937	\N	\N
4	2	Dell XPS 13	Dell XPS 13 with Intel i7, 16GB RAM, and 512GB SSD	129999.00	75	2024-10-17 15:47:22.655937	\N	\N
5	3	Sony Bravia 55"	Sony Bravia 4K Ultra HD Smart TV 55-inch	79999.00	40	2024-10-17 15:47:22.655937	\N	\N
6	3	Bose Soundbar 700	Bose premium soundbar with Alexa voice control	59999.00	60	2024-10-17 15:47:22.655937	\N	\N
7	4	Samsung Refrigerator	Samsung 600L double-door refrigerator with water dispenser	119999.00	30	2024-10-17 15:47:22.655937	\N	\N
8	4	LG Washing Machine	LG 9kg front-loading washing machine with inverter technology	69999.00	45	2024-10-17 15:47:22.655937	\N	\N
9	5	Canon EOS R5	Canon EOS R5 mirrorless camera with 45MP sensor	389999.00	20	2024-10-17 15:47:22.655937	\N	\N
10	6	Logitech MX Master 3	Logitech MX Master 3 advanced wireless mouse	9999.00	200	2024-10-17 15:47:22.655937	\N	\N
1	1	iPhone 14 Pro Max	Apple iPhone 14 Pro Max with 256GB storage, A16 chip	129999.00	100	2024-10-17 15:47:22.655937	C:\\Users\\tmshp\\OneDrive\\Рабочий стол\\iphone_12_PNG36.png	\N
\.


--
-- TOC entry 5028 (class 0 OID 16620)
-- Dependencies: 230
-- Data for Name: user_logs; Type: TABLE DATA; Schema: public; Owner: postgres
--

COPY public.user_logs (log_id, user_id, action, old_data, new_data, changed_at) FROM stdin;
1	14	INSERT	\N	{"email": "mot.white@example.com", "phone": "+123456789", "address": "Address", "user_id": 14, "password": "$2a$06$zRBYJyxvPV5xPbaiBJgjaOPd4A61G/eUHdaQ6E4CCTnyBWEveRFGK", "last_name": "White", "first_name": "Mot", "registration_date": "2024-10-24T16:36:45.777508"}	2024-10-24 16:36:45.777508
2	15	INSERT	\N	{"email": "admin@mail.ru", "phone": "89045828897", "address": "Омск, Ленина, 28", "user_id": 15, "password": "$2a$06$bG74S9oJSdCffuswtGmviOHpQvvehb0WjnzpgPedFuyX/jPtD0mEu", "last_name": "Проскурин", "first_name": "Тимофей", "registration_date": "2025-03-07T07:02:34.771172"}	2025-03-07 13:02:34.545836
3	16	INSERT	\N	{"email": "admin@gmail.ru", "phone": "89045828897", "address": "Омск, Ленина, 28", "user_id": 16, "password": "$2a$06$B8QZYhGg1CwdD4qndxv9Ye2gIShgABIv/fvSbOMbiynZgqylXIo.a", "last_name": "Проскурин", "first_name": "Тимофей", "registration_date": "2025-03-07T07:15:27.73185"}	2025-03-07 13:15:27.529094
4	6	DELETE	{"email": "john.doe@techstore.com", "phone": "+79112223333", "address": "Moscow, Tverskaya St, 15", "user_id": 6, "password": "$2a$06$7ma4ccTnTzp4nphmbCJ.NOAhYFPOdHcqW4Iegi2B.S0.C5x67LQ5O", "last_name": "Doe", "first_name": "John", "registration_date": "2024-10-17T16:19:08.719941"}	\N	2025-03-27 16:05:21.428412
5	17	INSERT	\N	{"email": "adign@gmail.ru", "phone": "89045828896", "address": "Омск, Ленина, 28", "user_id": 17, "password": "$2a$06$CiEd4/k15j.8BDDIiE.r3ujSVWrc9r1itZWmuBqnNxUlIWr.NAHE.", "last_name": "Проскурин", "first_name": "Тимофей", "registration_date": "2025-03-27T16:09:59.411712"}	2025-03-27 16:09:59.411712
6	18	INSERT	\N	{"email": "test@mail.ru", "phone": "89045828897", "address": "Омск, Ленина, 28", "user_id": 18, "password": "$2a$06$z4A6KvsLRESIByqbcmcVRu9XbZTHjpugylB1z1qMe8fKaPH.EEUV2", "last_name": "Проскурин", "first_name": "Тимофей", "registration_date": "2025-04-14T18:03:55.68798"}	2025-04-14 18:03:55.68798
7	15	DELETE	{"email": "admin@mail.ru", "phone": "89045828897", "address": "Омск, Ленина, 28", "user_id": 15, "password": "$2a$06$bG74S9oJSdCffuswtGmviOHpQvvehb0WjnzpgPedFuyX/jPtD0mEu", "last_name": "Проскурин", "first_name": "Тимофей", "registration_date": "2025-03-07T07:02:34.771172"}	\N	2025-04-14 18:08:59.790052
8	16	DELETE	{"email": "admin@gmail.ru", "phone": "89045828897", "address": "Омск, Ленина, 28", "user_id": 16, "password": "$2a$06$B8QZYhGg1CwdD4qndxv9Ye2gIShgABIv/fvSbOMbiynZgqylXIo.a", "last_name": "Проскурин", "first_name": "Тимофей", "registration_date": "2025-03-07T07:15:27.73185"}	\N	2025-04-14 18:08:59.790052
9	17	DELETE	{"email": "adign@gmail.ru", "phone": "89045828896", "address": "Омск, Ленина, 28", "user_id": 17, "password": "$2a$06$CiEd4/k15j.8BDDIiE.r3ujSVWrc9r1itZWmuBqnNxUlIWr.NAHE.", "last_name": "Проскурин", "first_name": "Тимофей", "registration_date": "2025-03-27T16:09:59.411712"}	\N	2025-04-14 18:08:59.790052
10	19	INSERT	\N	{"email": "string@gmail.com", "phone": "89048957757", "address": "string", "user_id": 19, "password": "$2a$06$OdSzag7rciiQ/eD.G5ENfeN.CVszacj4ebSYNdTVUeTA.CYz01faK", "last_name": "string", "first_name": "string", "registration_date": "2025-04-14T12:25:19.39793"}	2025-04-14 18:25:19.396039
11	18	DELETE	{"email": "test@mail.ru", "phone": "89045828897", "address": "Омск, Ленина, 28", "user_id": 18, "password": "$2a$06$z4A6KvsLRESIByqbcmcVRu9XbZTHjpugylB1z1qMe8fKaPH.EEUV2", "last_name": "Проскурин", "first_name": "Тимофей", "registration_date": "2025-04-14T18:03:55.68798"}	\N	2025-04-14 18:25:54.827849
12	20	INSERT	\N	{"email": "adign@gmail.ru", "phone": "89045828896", "address": "Омск, Ленина, 28", "user_id": 20, "password": "$2a$06$ZJKsOrdA64vtlDV0iuI/qOTIBkUykscG0C8olFY2FTu5xHNmwt7Zm", "last_name": "Проскурин", "first_name": "Тимофей", "registration_date": "2025-04-14T12:26:05.998343"}	2025-04-14 18:26:05.997843
13	21	INSERT	\N	{"email": "adign@gmail.xn--ru-olc", "phone": "89045824342", "address": "Омск, Ленина, 28", "user_id": 21, "password": "$2a$06$QJn6AAycqgqCJws7CaiaR.j1aVeIwBDfVwP/qKaheBbvqk1vt7tpa", "last_name": "Проскурин", "first_name": "Тимофей", "secret_key": "gAAAAABn_0fFDC6jTTSU-Cd0GFqrDHyISEawM_pjJwIJl_kRm5XIzfCl-CbJBLWEsAKynAI_BosmVF3yLPIPXM2LyHpbpEf_ap0LtYyMKz7cnG498ZFgYrN58DZafx04qf9_e_wt7_tT", "two_fa_enabled": false, "registration_date": "2025-04-16T06:01:41.306044"}	2025-04-16 12:01:41.302656
14	22	INSERT	\N	{"email": "adign@gmail.kdf", "phone": "89045828844", "address": "Омск, Ленина, 28", "user_id": 22, "password": "$2a$06$7Ln.0hnMcuBm.RNS7/jDKeBS3G7n7ZXZXYhVMMZeRBUimY.kURtXq", "last_name": "Проскурин", "first_name": "Тимофей", "secret_key": null, "two_fa_enabled": false, "registration_date": "2025-04-29T13:38:26.755573"}	2025-04-29 19:38:26.727868
15	23	INSERT	\N	{"email": "adign@gmail.sdfsd", "phone": "89045828896", "address": "Омск, Ленина, 28", "user_id": 23, "password": "$2a$06$SO9.Vg4Y.Ud53ayayMUdYe5mm2QgeqGEFJRT5ycKM2/wUUmudbnFG", "last_name": "Проскурин", "first_name": "Тимофей", "secret_key": null, "two_fa_enabled": false, "registration_date": "2025-05-07T06:59:30.547346"}	2025-05-07 12:59:30.546807
16	24	INSERT	\N	{"email": "adign@gmail.xsas", "phone": "89045828896", "address": "Омск, Ленина, 28", "user_id": 24, "password": "$2a$06$eUidNAffVJ35hnql0bKMTOyQrEDgBtfJV1j6yOTYQxnpJj5hoJRZ.", "last_name": "Проскурин", "first_name": "Тимофей", "secret_key": null, "two_fa_enabled": false, "registration_date": "2025-05-07T09:36:30.495739"}	2025-05-07 15:36:30.494561
\.


--
-- TOC entry 5030 (class 0 OID 16627)
-- Dependencies: 232
-- Data for Name: users; Type: TABLE DATA; Schema: public; Owner: postgres
--

COPY public.users (user_id, first_name, last_name, email, phone, address, registration_date, password, secret_key, two_fa_enabled) FROM stdin;
1	Alexey	Ivanov	alexey.ivanov@techstore.com	+79112223344	Moscow, Tverskaya St, 12	2024-10-17 15:47:22.655937	$2a$06$M.6cgqX1C86A8LM3TSBFNumH7VT6p./M8076ALnJNvLcotYSK7NAO	\N	f
2	Maria	Petrova	maria.petrova@techstore.com	+79212223355	Saint Petersburg, Nevsky Ave, 24	2024-10-17 15:47:22.655937	$2a$06$9jnXs.drZ5KhkufCfZLiC.7dP0q032GD81zzUFpNYedYpU5YhGolO	\N	f
3	Sergey	Kuznetsov	sergey.kuznetsov@techstore.com	+79312223366	Novosibirsk, Lenin St, 3	2024-10-17 15:47:22.655937	$2a$06$yuHjFCc/BhAh9Ctc7sPHa.PeL.glc9LvhhBZ/2ZvhvKk.O6H8syn2	\N	f
4	Elena	Sidorova	elena.sidorova@techstore.com	+79412223377	Kazan, Bauman St, 5	2024-10-17 15:47:22.655937	$2a$06$gwyeVuP59fAadHC.OeTazehgUrMC.n.ZURrnN8tQQM444PBqXscse	\N	f
5	Oleg	Orlov	oleg.orlov@techstore.com	+79512223388	Yekaterinburg, Vysotsky St, 8	2024-10-17 15:47:22.655937	$2a$06$EFJ14bKfJvs0EWCPBo049.4Zkqk986GpDTn/VSM8yuAALwEGV/3aC	\N	f
9	Alice	Smith	alice.smith@example.com	+0987654321	\\xc30d040703027f298a5c076f57f67bd24b01b60d7747bc228fedffcb3bdedc23f434ee337ccc338d04e82880e983473a749853c68df5404c1cf1bfb2a54dc62df6c1db6dccd3ec9e316758c9bd4f0752d22976558e6ec2b4f5314a8b	2024-10-21 20:09:06.947794	$2a$06$FDxqk4zPR6uedmOkOzwzMOO5pnkPc3rcT64j8D4.w1/2hBOvbZ8P2	\N	f
11	John	Doe	john.doe@example.com	+123456789	\\xc30d040703023929e1e3adaad35f77d24701c088ca311ba82276139df639dec6ebe11aff6f9e4c205cfe6b34777905618e408c16383b303c0e23e9ff0c051c9341ff154bd0cf80bae685978be4da57a9d97e1e74cd3fd7bb	2024-10-23 13:11:14.747473	$2a$06$fXP5Q0BNVEDRYdWYQ7Cu8OB1DHT6NYxsDn6y9QPbVnkZx1srZA56C	\N	f
12	John	Smith	john.smith@gmail.com	+123456789	\\xc30d0407030223039d3285b37bac75d2480101ae395db86638c2e517fd87def21b77a024635f03f076c7fb836240ed3ac7b9527df5469cce15b2eb0fc15a11a1eafd481a5b35739c0d9c3f9e5959696c8c1a5f29c84e829393	2024-10-23 13:14:54.19637	$2a$06$/lfg9RNXrjVgS1ouBWkVYOmWK6zA8LxZUQxIQ209IOcUYrDBIVDR2	\N	f
14	Mot	White	mot.white@example.com	+123456789	Address	2024-10-24 16:36:45.777508	$2a$06$zRBYJyxvPV5xPbaiBJgjaOPd4A61G/eUHdaQ6E4CCTnyBWEveRFGK	\N	f
19	string	string	string@gmail.com	89048957757	string	2025-04-14 12:25:19.39793	$2a$06$OdSzag7rciiQ/eD.G5ENfeN.CVszacj4ebSYNdTVUeTA.CYz01faK	\N	f
20	Тимофей	Проскурин	adign@gmail.ru	89045828896	Омск, Ленина, 28	2025-04-14 12:26:05.998343	$2a$06$ZJKsOrdA64vtlDV0iuI/qOTIBkUykscG0C8olFY2FTu5xHNmwt7Zm	\N	f
21	Тимофей	Проскурин	adign@gmail.xn--ru-olc	89045824342	Омск, Ленина, 28	2025-04-16 06:01:41.306044	$2a$06$QJn6AAycqgqCJws7CaiaR.j1aVeIwBDfVwP/qKaheBbvqk1vt7tpa	gAAAAABn_0fFDC6jTTSU-Cd0GFqrDHyISEawM_pjJwIJl_kRm5XIzfCl-CbJBLWEsAKynAI_BosmVF3yLPIPXM2LyHpbpEf_ap0LtYyMKz7cnG498ZFgYrN58DZafx04qf9_e_wt7_tT	f
22	Тимофей	Проскурин	adign@gmail.kdf	89045828844	Омск, Ленина, 28	2025-04-29 13:38:26.755573	$2a$06$7Ln.0hnMcuBm.RNS7/jDKeBS3G7n7ZXZXYhVMMZeRBUimY.kURtXq	\N	f
23	Тимофей	Проскурин	adign@gmail.sdfsd	89045828896	Омск, Ленина, 28	2025-05-07 06:59:30.547346	$2a$06$SO9.Vg4Y.Ud53ayayMUdYe5mm2QgeqGEFJRT5ycKM2/wUUmudbnFG	\N	f
24	Тимофей	Проскурин	adign@gmail.xsas	89045828896	Омск, Ленина, 28	2025-05-07 09:36:30.495739	$2a$06$eUidNAffVJ35hnql0bKMTOyQrEDgBtfJV1j6yOTYQxnpJj5hoJRZ.	\N	f
\.


--
-- TOC entry 5047 (class 0 OID 0)
-- Dependencies: 217
-- Name: categories_category_id_seq; Type: SEQUENCE SET; Schema: public; Owner: postgres
--

SELECT pg_catalog.setval('public.categories_category_id_seq', 6, true);


--
-- TOC entry 5048 (class 0 OID 0)
-- Dependencies: 219
-- Name: delivery_delivery_id_seq; Type: SEQUENCE SET; Schema: public; Owner: postgres
--

SELECT pg_catalog.setval('public.delivery_delivery_id_seq', 5, true);


--
-- TOC entry 5049 (class 0 OID 0)
-- Dependencies: 221
-- Name: encryptionkeys_key_id_seq; Type: SEQUENCE SET; Schema: public; Owner: postgres
--

SELECT pg_catalog.setval('public.encryptionkeys_key_id_seq', 3, true);


--
-- TOC entry 5050 (class 0 OID 0)
-- Dependencies: 223
-- Name: orderitems_order_item_id_seq; Type: SEQUENCE SET; Schema: public; Owner: postgres
--

SELECT pg_catalog.setval('public.orderitems_order_item_id_seq', 7, true);


--
-- TOC entry 5051 (class 0 OID 0)
-- Dependencies: 225
-- Name: orders_order_id_seq; Type: SEQUENCE SET; Schema: public; Owner: postgres
--

SELECT pg_catalog.setval('public.orders_order_id_seq', 5, true);


--
-- TOC entry 5052 (class 0 OID 0)
-- Dependencies: 227
-- Name: payments_payment_id_seq; Type: SEQUENCE SET; Schema: public; Owner: postgres
--

SELECT pg_catalog.setval('public.payments_payment_id_seq', 11, true);


--
-- TOC entry 5053 (class 0 OID 0)
-- Dependencies: 229
-- Name: products_product_id_seq; Type: SEQUENCE SET; Schema: public; Owner: postgres
--

SELECT pg_catalog.setval('public.products_product_id_seq', 10, true);


--
-- TOC entry 5054 (class 0 OID 0)
-- Dependencies: 231
-- Name: user_logs_log_id_seq; Type: SEQUENCE SET; Schema: public; Owner: postgres
--

SELECT pg_catalog.setval('public.user_logs_log_id_seq', 16, true);


--
-- TOC entry 5055 (class 0 OID 0)
-- Dependencies: 233
-- Name: users_user_id_seq; Type: SEQUENCE SET; Schema: public; Owner: postgres
--

SELECT pg_catalog.setval('public.users_user_id_seq', 24, true);


--
-- TOC entry 4837 (class 2606 OID 16644)
-- Name: categories categories_pkey; Type: CONSTRAINT; Schema: public; Owner: postgres
--

ALTER TABLE ONLY public.categories
    ADD CONSTRAINT categories_pkey PRIMARY KEY (category_id);


--
-- TOC entry 4839 (class 2606 OID 16646)
-- Name: delivery delivery_pkey; Type: CONSTRAINT; Schema: public; Owner: postgres
--

ALTER TABLE ONLY public.delivery
    ADD CONSTRAINT delivery_pkey PRIMARY KEY (delivery_id);


--
-- TOC entry 4841 (class 2606 OID 16648)
-- Name: encryptionkeys encryptionkeys_pkey; Type: CONSTRAINT; Schema: public; Owner: postgres
--

ALTER TABLE ONLY public.encryptionkeys
    ADD CONSTRAINT encryptionkeys_pkey PRIMARY KEY (key_id);


--
-- TOC entry 4843 (class 2606 OID 16650)
-- Name: orderitems orderitems_pkey; Type: CONSTRAINT; Schema: public; Owner: postgres
--

ALTER TABLE ONLY public.orderitems
    ADD CONSTRAINT orderitems_pkey PRIMARY KEY (order_item_id);


--
-- TOC entry 4845 (class 2606 OID 16652)
-- Name: orders orders_pkey; Type: CONSTRAINT; Schema: public; Owner: postgres
--

ALTER TABLE ONLY public.orders
    ADD CONSTRAINT orders_pkey PRIMARY KEY (order_id);


--
-- TOC entry 4847 (class 2606 OID 16654)
-- Name: payments payments_pkey; Type: CONSTRAINT; Schema: public; Owner: postgres
--

ALTER TABLE ONLY public.payments
    ADD CONSTRAINT payments_pkey PRIMARY KEY (payment_id);


--
-- TOC entry 4849 (class 2606 OID 16656)
-- Name: products products_pkey; Type: CONSTRAINT; Schema: public; Owner: postgres
--

ALTER TABLE ONLY public.products
    ADD CONSTRAINT products_pkey PRIMARY KEY (product_id);


--
-- TOC entry 4851 (class 2606 OID 16658)
-- Name: user_logs user_logs_pkey; Type: CONSTRAINT; Schema: public; Owner: postgres
--

ALTER TABLE ONLY public.user_logs
    ADD CONSTRAINT user_logs_pkey PRIMARY KEY (log_id);


--
-- TOC entry 4853 (class 2606 OID 16660)
-- Name: users users_email_key; Type: CONSTRAINT; Schema: public; Owner: postgres
--

ALTER TABLE ONLY public.users
    ADD CONSTRAINT users_email_key UNIQUE (email);


--
-- TOC entry 4855 (class 2606 OID 16662)
-- Name: users users_pkey; Type: CONSTRAINT; Schema: public; Owner: postgres
--

ALTER TABLE ONLY public.users
    ADD CONSTRAINT users_pkey PRIMARY KEY (user_id);


--
-- TOC entry 4863 (class 2620 OID 16663)
-- Name: payments before_insert_payments; Type: TRIGGER; Schema: public; Owner: postgres
--

CREATE TRIGGER before_insert_payments BEFORE INSERT ON public.payments FOR EACH ROW EXECUTE FUNCTION public.encrypt_payment_data();


--
-- TOC entry 4864 (class 2620 OID 16664)
-- Name: users before_insert_users; Type: TRIGGER; Schema: public; Owner: postgres
--

CREATE TRIGGER before_insert_users BEFORE INSERT ON public.users FOR EACH ROW EXECUTE FUNCTION public.hash_password();


--
-- TOC entry 4865 (class 2620 OID 16665)
-- Name: users user_changes_trigger; Type: TRIGGER; Schema: public; Owner: postgres
--

CREATE TRIGGER user_changes_trigger AFTER INSERT OR DELETE OR UPDATE ON public.users FOR EACH ROW EXECUTE FUNCTION public.log_user_changes();


--
-- TOC entry 4856 (class 2606 OID 16666)
-- Name: delivery delivery_order_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: postgres
--

ALTER TABLE ONLY public.delivery
    ADD CONSTRAINT delivery_order_id_fkey FOREIGN KEY (order_id) REFERENCES public.orders(order_id);


--
-- TOC entry 4857 (class 2606 OID 16671)
-- Name: encryptionkeys encryptionkeys_user_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: postgres
--

ALTER TABLE ONLY public.encryptionkeys
    ADD CONSTRAINT encryptionkeys_user_id_fkey FOREIGN KEY (user_id) REFERENCES public.users(user_id);


--
-- TOC entry 4858 (class 2606 OID 16676)
-- Name: orderitems orderitems_order_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: postgres
--

ALTER TABLE ONLY public.orderitems
    ADD CONSTRAINT orderitems_order_id_fkey FOREIGN KEY (order_id) REFERENCES public.orders(order_id);


--
-- TOC entry 4859 (class 2606 OID 16681)
-- Name: orderitems orderitems_product_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: postgres
--

ALTER TABLE ONLY public.orderitems
    ADD CONSTRAINT orderitems_product_id_fkey FOREIGN KEY (product_id) REFERENCES public.products(product_id);


--
-- TOC entry 4860 (class 2606 OID 16686)
-- Name: orders orders_user_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: postgres
--

ALTER TABLE ONLY public.orders
    ADD CONSTRAINT orders_user_id_fkey FOREIGN KEY (user_id) REFERENCES public.users(user_id);


--
-- TOC entry 4861 (class 2606 OID 16691)
-- Name: payments payments_order_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: postgres
--

ALTER TABLE ONLY public.payments
    ADD CONSTRAINT payments_order_id_fkey FOREIGN KEY (order_id) REFERENCES public.orders(order_id);


--
-- TOC entry 4862 (class 2606 OID 16696)
-- Name: products products_category_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: postgres
--

ALTER TABLE ONLY public.products
    ADD CONSTRAINT products_category_id_fkey FOREIGN KEY (category_id) REFERENCES public.categories(category_id);


--
-- TOC entry 5011 (class 3256 OID 16701)
-- Name: users admin_moderator_access_policy; Type: POLICY; Schema: public; Owner: postgres
--

CREATE POLICY admin_moderator_access_policy ON public.users FOR SELECT USING ((CURRENT_USER = ANY (ARRAY['admin'::name, 'moderator'::name])));


--
-- TOC entry 5009 (class 0 OID 16593)
-- Dependencies: 220
-- Name: encryptionkeys; Type: ROW SECURITY; Schema: public; Owner: postgres
--

ALTER TABLE public.encryptionkeys ENABLE ROW LEVEL SECURITY;

--
-- TOC entry 5012 (class 3256 OID 16702)
-- Name: encryptionkeys user_access_policy; Type: POLICY; Schema: public; Owner: postgres
--

CREATE POLICY user_access_policy ON public.encryptionkeys FOR SELECT USING ((user_id = ( SELECT users.user_id
   FROM public.users
  WHERE ((users.email)::text = CURRENT_USER))));


--
-- TOC entry 5013 (class 3256 OID 16703)
-- Name: users user_access_policy; Type: POLICY; Schema: public; Owner: postgres
--

CREATE POLICY user_access_policy ON public.users FOR SELECT USING (((email)::text = CURRENT_USER));


--
-- TOC entry 5010 (class 0 OID 16627)
-- Dependencies: 232
-- Name: users; Type: ROW SECURITY; Schema: public; Owner: postgres
--

ALTER TABLE public.users ENABLE ROW LEVEL SECURITY;

-- Completed on 2025-05-22 13:00:02

--
-- PostgreSQL database dump complete
--

