import { createBrowserRouter } from "react-router";
import Login from "./pages/login";
import Home from "./pages/home";

export const router = createBrowserRouter([
  {
    path: "/",
    element: <Home />,
  },
  {
    path: "/login",
    element: <Login />,
  },
]);
