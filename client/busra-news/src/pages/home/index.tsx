import { Button } from "@/components/ui/button";
import { Link } from "react-router";

const Home = () => {
  return (
    <div className="min-h-screen w-full bg-muted px-4">
      <div className="w-full max-w-4xl mx-auto py-4">
        <div className="bg-primary/5 p-4 border border-primary/10 rounded-xl flex items-center justify-between gap-4">
          <Link to={"/"} className="text-2xl font-semibold text-primary">Todo List</Link>
          <Button>Add New</Button>
        </div>
      </div>
    </div>
  );
};

export default Home;
