import apiSlice from "../api-queries/api-slice";

const authApi = apiSlice.injectEndpoints({
  endpoints: (builder) => ({
    // === google login ===
    googleLogin: builder.mutation({
      query: ({ payload }) => ({
        url: `/admin/login`,
        method: "POST",
        body: payload,
      }),
      invalidatesTags: ["USER"],
    }),
  }),
});

export const { useGoogleLoginMutation } = authApi;
