"""
In this file we define a ProblemVault class where we store all the
exceptions and all the problems we find with the code.

The ProblemVault is capable of registering problems and also figuring out if a
problem is worse than a registered exception so that it only warns when things
get worse.
"""

class ProblemVault(object):
    """
    Singleton where we store the various new problems we
    found in the code, and also the old problems we read from the exception
    file.
    """
    def __init__(self, exception_fname):
        # Exception dictionary: { problem.key() : Problem object }
        self.exceptions = {}

        try:
            with open(exception_fname, 'r') as exception_f:
                self.register_exceptions(exception_f)
        except IOError:
            print("No exception file provided")

    def register_exceptions(self, exception_file):
        # Register exceptions
        for line in exception_file:
            problem = get_old_problem_from_exception_str(line)
            if problem is None:
                continue

            self.exceptions[problem.key()] = problem
            #print "Registering exception: %s" % problem

    def register_problem(self, problem):
        """
        Register this problem to the problem value. Return True if it was a new
        problem or it worsens an already existing problem.
        """
        # This is a new problem, print it
        if problem.key() not in self.exceptions:
            print(problem)
            return True

        # If it's an old problem, we don't warn if the situation got better
        # (e.g. we went from 4k LoC to 3k LoC), but we do warn if the
        # situation worsened (e.g. we went from 60 includes to 80).
        if problem.is_worse_than(self.exceptions[problem.key()]):
            print(problem)
            return True

        return False

class Problem(object):
    def __init__(self, problem_type, problem_location, metric_value):
        self.problem_location = problem_location
        self.metric_value = int(metric_value)
        self.problem_type = problem_type

    def is_worse_than(self, other_problem):
        """Return True if this is a worse problem than other_problem"""
        if self.metric_value > other_problem.metric_value:
            return True
        return False

    def key(self):
        """Generate a unique key that describes this problem that can be used as a dictionary key"""
        return "%s:%s" % (self.problem_location, self.problem_type)

    def __str__(self):
        return "problem %s %s %s" % (self.problem_type, self.problem_location, self.metric_value)

class FileSizeProblem(Problem):
    def __init__(self, problem_location, metric_value):
        super(FileSizeProblem, self).__init__("file-size", problem_location, metric_value)

class IncludeCountProblem(Problem):
    def __init__(self, problem_location, metric_value):
        super(IncludeCountProblem, self).__init__("include-count", problem_location, metric_value)

class FunctionSizeProblem(Problem):
    def __init__(self, problem_location, metric_value):
        super(FunctionSizeProblem, self).__init__("function-size", problem_location, metric_value)

def get_old_problem_from_exception_str(exception_str):
    try:
        _, problem_type, problem_location, metric_value = exception_str.split(" ")
    except ValueError:
        return None

    if problem_type == "file-size":
        return FileSizeProblem(problem_location, metric_value)
    elif problem_type == "include-count":
        return IncludeCountProblem(problem_location, metric_value)
    elif problem_type == "function-size":
        return FunctionSizeProblem(problem_location, metric_value)
    else:
#        print("Unknown exception line '{}'".format(exception_str))
        return None

