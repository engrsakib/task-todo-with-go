import apiSlice from "../api-queries/api-slice";

const todoApi = apiSlice.injectEndpoints({
  endpoints: (builder) => ({
    // === create todo ===
    createTodo: builder.mutation({
      query: ({ payload }) => ({
        url: `/todo`,
        method: "POST",
        body: payload,
      }),
      invalidatesTags: ["TODOS"],
    }),

    // === get all todos ===
    getAllTodos: builder.query({
      query: () => ({
        url: `/todo`,
        method: "GET",
      }),
      providesTags: ["TODOS"],
    }),

    // === get single todos ===
    getSingleTodo: builder.query({
      query: ({ todoId }) => ({
        url: `/todo/${todoId}`,
        method: "GET",
      }),
    }),

    // === update todo ===
    updateTodo: builder.mutation({
      query: ({ todoId, payload }) => ({
        url: `/todo/${todoId}`,
        method: "PATCH",
        body: payload,
      }),
      invalidatesTags: ["TODOS"],
    }),

    // === delete todo ===
    deleteTodo: builder.mutation({
      query: ({ todoId }) => ({
        url: `/todo/${todoId}`,
        method: "DELETE",
      }),
      invalidatesTags: ["TODOS"],
    }),
  }),
});

export const {
  useCreateTodoMutation,
  useGetAllTodosQuery,
  useGetSingleTodoQuery,
  useUpdateTodoMutation,
  useDeleteTodoMutation,
} = todoApi;
