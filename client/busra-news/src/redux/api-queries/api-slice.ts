"use client";

import { ENV } from "@/config/env";
import { fetchBaseQuery } from "@reduxjs/toolkit/query";
import { createApi } from "@reduxjs/toolkit/query/react";

const baseQuery = fetchBaseQuery({
  baseUrl: ENV.API_BASE_URL,
  credentials: "include",
});

const apiSlice = createApi({
  reducerPath: "api",
  baseQuery,
  endpoints: () => ({}),
  tagTypes: ["USER", "TODOS"],
});

export default apiSlice;
