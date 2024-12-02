--
-- PostgreSQL database dump
--

-- Dumped from database version 17.2
-- Dumped by pg_dump version 17.2

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

SET default_tablespace = '';

SET default_table_access_method = heap;

--
-- Name: ourusers; Type: TABLE; Schema: public; Owner: postgres
--

CREATE TABLE public.ourusers (
    id integer NOT NULL,
    city character varying(255),
    email character varying(255),
    name character varying(255),
    password character varying(255),
    role character varying(255)
);


ALTER TABLE public.ourusers OWNER TO postgres;

--
-- Name: ourusers_id_seq; Type: SEQUENCE; Schema: public; Owner: postgres
--

ALTER TABLE public.ourusers ALTER COLUMN id ADD GENERATED BY DEFAULT AS IDENTITY (
    SEQUENCE NAME public.ourusers_id_seq
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1
);


--
-- Data for Name: ourusers; Type: TABLE DATA; Schema: public; Owner: postgres
--

COPY public.ourusers (id, city, email, name, password, role) FROM stdin;
1	Town	admin@gmail.com	admin	$2a$10$HLdlIvP6y8cRXyOcH6x9yeDW7JoFogdCOCXxwSWeKD5lT2U7OmxaC	User
2	Jaffna	Admin@gmail.com	Admin	$2a$10$i3vPP3bmrDDeDxpqxW/VMuXlCfcn9gMTUlfomOmtYoSn740orRNOC	Admin
3	PointPedro	User@gmail.com	User	$2a$10$YYuzrDw/lWuzCGNGCLVCxeCWRoECcFPT.lyVBxy9iG8VmKGryd5kq	User
4	Jaffna	Admin@gmail.com	AAA	$2a$10$bRfCEleoQZwuUDZRY.eozevMm8OXRjXpMH63kSb31sBMlIGLyfYYK	ADMIN
\.


--
-- Name: ourusers_id_seq; Type: SEQUENCE SET; Schema: public; Owner: postgres
--

SELECT pg_catalog.setval('public.ourusers_id_seq', 4, true);


--
-- Name: ourusers ourusers_pkey; Type: CONSTRAINT; Schema: public; Owner: postgres
--

ALTER TABLE ONLY public.ourusers
    ADD CONSTRAINT ourusers_pkey PRIMARY KEY (id);


--
-- PostgreSQL database dump complete
--

